#include "acme_client.hpp"

#include <arpa/inet.h>
#include <algorithm>
#include <array>
#include <cassert>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <sstream>
#include <sys/socket.h>
#include <sys/stat.h>
#include <thread>
#include <unordered_map>
#include <unistd.h>

namespace {

bool receive_request(int client, std::string& request) {
    char buffer[2048];
    size_t body_start = std::string::npos;
    size_t content_length = 0;
    while (true) {
        ssize_t count = recv(client, buffer, sizeof(buffer), 0);
        if (count <= 0) return false;
        request.append(buffer, static_cast<size_t>(count));
        if (body_start == std::string::npos) {
            body_start = request.find("\r\n\r\n");
            if (body_start == std::string::npos) continue;
            std::istringstream headers(request.substr(0, body_start));
            std::string line;
            std::getline(headers, line);
            while (std::getline(headers, line)) {
                if (!line.empty() && line.back() == '\r') line.pop_back();
                auto colon = line.find(':');
                if (colon == std::string::npos) continue;
                std::string name = line.substr(0, colon);
                for (auto& ch : name) ch = static_cast<char>(std::tolower(
                    static_cast<unsigned char>(ch)));
                if (name == "content-length") {
                    content_length = static_cast<size_t>(std::stoul(line.substr(colon + 1)));
                }
            }
            body_start += 4;
        }
        if (request.size() - body_start >= content_length) return true;
    }
}

bool send_response(int client, const std::string& response) {
    size_t sent = 0;
    while (sent < response.size()) {
        ssize_t count = send(client, response.data() + sent, response.size() - sent,
                             MSG_NOSIGNAL);
        if (count <= 0) return false;
        sent += static_cast<size_t>(count);
    }
    return true;
}

std::string base64url_decode(std::string_view input) {
    std::string decoded;
    unsigned accumulator = 0;
    int bits = 0;
    for (unsigned char ch : input) {
        unsigned value;
        if (ch >= 'A' && ch <= 'Z') value = ch - 'A';
        else if (ch >= 'a' && ch <= 'z') value = ch - 'a' + 26;
        else if (ch >= '0' && ch <= '9') value = ch - '0' + 52;
        else if (ch == '-') value = 62;
        else if (ch == '_') value = 63;
        else return {};
        accumulator = (accumulator << 6) | value;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            decoded += static_cast<char>((accumulator >> bits) & 0xff);
        }
    }
    return decoded;
}

std::string json_string_field(std::string_view json, std::string_view key) {
    std::string marker = "\"" + std::string(key) + "\":\"";
    auto start = json.find(marker);
    if (start == std::string_view::npos) return {};
    start += marker.size();
    auto end = json.find('"', start);
    if (end == std::string_view::npos) return {};
    return std::string(json.substr(start, end - start));
}

bool verify_es256_jws(std::string_view protected64, std::string_view payload64,
                      std::string_view signature_raw, std::string_view protected_json) {
    auto x_bytes = base64url_decode(json_string_field(protected_json, "x"));
    auto y_bytes = base64url_decode(json_string_field(protected_json, "y"));
    if (x_bytes.size() != 32 || y_bytes.size() != 32 || signature_raw.size() != 64)
        return false;
    BIGNUM* x = BN_bin2bn(reinterpret_cast<const unsigned char*>(x_bytes.data()),
                          static_cast<int>(x_bytes.size()), nullptr);
    BIGNUM* y = BN_bin2bn(reinterpret_cast<const unsigned char*>(y_bytes.data()),
                          static_cast<int>(y_bytes.size()), nullptr);
    std::array<unsigned char, 65> public_point{};
    public_point[0] = 4;
    std::memcpy(public_point.data() + 1, x_bytes.data(), 32);
    std::memcpy(public_point.data() + 33, y_bytes.data(), 32);
    OSSL_PARAM_BLD* builder = OSSL_PARAM_BLD_new();
    bool ok = x && y && builder &&
              OSSL_PARAM_BLD_push_utf8_string(builder, OSSL_PKEY_PARAM_GROUP_NAME,
                                               "prime256v1", 0) == 1 &&
              OSSL_PARAM_BLD_push_octet_string(builder, OSSL_PKEY_PARAM_PUB_KEY,
                                                public_point.data(), public_point.size()) == 1;
    OSSL_PARAM* params = ok ? OSSL_PARAM_BLD_to_param(builder) : nullptr;
    EVP_PKEY_CTX* key_context = EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr);
    EVP_PKEY* public_key = nullptr;
    ok = ok && params && key_context && EVP_PKEY_fromdata_init(key_context) == 1 &&
         EVP_PKEY_fromdata(key_context, &public_key, EVP_PKEY_PUBLIC_KEY, params) == 1;
    if (!ok) std::cerr << "JWS test: failed to construct public key\n";

    ECDSA_SIG* signature = ECDSA_SIG_new();
    BIGNUM* r = BN_bin2bn(reinterpret_cast<const unsigned char*>(signature_raw.data()), 32, nullptr);
    BIGNUM* s = BN_bin2bn(reinterpret_cast<const unsigned char*>(signature_raw.data() + 32),
                          32, nullptr);
    ok = ok && signature && r && s && ECDSA_SIG_set0(signature, r, s) == 1;
    if (ok) {
        r = nullptr;
        s = nullptr;
    }
    int der_size = ok ? i2d_ECDSA_SIG(signature, nullptr) : 0;
    std::vector<unsigned char> der(static_cast<size_t>(std::max(der_size, 0)));
    if (der_size > 0) {
        unsigned char* cursor = der.data();
        ok = i2d_ECDSA_SIG(signature, &cursor) == der_size;
    } else {
        ok = false;
    }
    if (!ok) std::cerr << "JWS test: failed to parse raw signature\n";
    EVP_MD_CTX* digest_context = ok ? EVP_MD_CTX_new() : nullptr;
    std::string signing_input = std::string(protected64) + "." + std::string(payload64);
    if (!ok || !digest_context ||
        EVP_DigestVerifyInit(digest_context, nullptr, EVP_sha256(), nullptr, public_key) != 1 ||
        EVP_DigestVerifyUpdate(digest_context, signing_input.data(), signing_input.size()) != 1) {
        std::cerr << "JWS test: verifier setup failed\n";
        ok = false;
    } else if (EVP_DigestVerifyFinal(digest_context, der.data(), der.size()) != 1) {
        std::cerr << "JWS test: signature verification failed\n";
        ok = false;
    }

    EVP_MD_CTX_free(digest_context);
    BN_free(r);
    BN_free(s);
    ECDSA_SIG_free(signature);
    EVP_PKEY_free(public_key);
    EVP_PKEY_CTX_free(key_context);
    OSSL_PARAM_free(params);
    OSSL_PARAM_BLD_free(builder);
    BN_free(x);
    BN_free(y);
    return ok;
}

std::string certificate_for_csr(std::string_view csr_der) {
    const unsigned char* cursor = reinterpret_cast<const unsigned char*>(csr_der.data());
    X509_REQ* request = d2i_X509_REQ(nullptr, &cursor, static_cast<long>(csr_der.size()));
    if (!request) return {};
    EVP_PKEY* public_key = X509_REQ_get_pubkey(request);
    EVP_PKEY_CTX* key_context = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY* issuer_key = nullptr;
    bool ok = key_context && EVP_PKEY_keygen_init(key_context) > 0 &&
              EVP_PKEY_CTX_set_ec_paramgen_curve_nid(key_context, NID_X9_62_prime256v1) > 0 &&
              EVP_PKEY_keygen(key_context, &issuer_key) > 0;
    X509* certificate = ok ? X509_new() : nullptr;
    ok = ok && certificate && public_key &&
         X509_set_version(certificate, 2) == 1 &&
         ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1) == 1 &&
         X509_gmtime_adj(X509_getm_notBefore(certificate), 0) != nullptr &&
         X509_gmtime_adj(X509_getm_notAfter(certificate), 30 * 24 * 60 * 60) != nullptr &&
         X509_set_subject_name(certificate, X509_REQ_get_subject_name(request)) == 1 &&
         X509_set_issuer_name(certificate, X509_REQ_get_subject_name(request)) == 1 &&
         X509_set_pubkey(certificate, public_key) == 1;
    STACK_OF(X509_EXTENSION)* extensions = X509_REQ_get_extensions(request);
    if (ok && extensions) {
        for (int i = 0; i < sk_X509_EXTENSION_num(extensions); ++i) {
            if (X509_add_ext(certificate, sk_X509_EXTENSION_value(extensions, i), -1) != 1) {
                ok = false;
                break;
            }
        }
    } else {
        ok = false;
    }
    ok = ok && X509_sign(certificate, issuer_key, EVP_sha256()) > 0;
    BIO* output = ok ? BIO_new(BIO_s_mem()) : nullptr;
    ok = ok && output && PEM_write_bio_X509(output, certificate) == 1;
    std::string pem;
    if (ok) {
        char* data = nullptr;
        long length = BIO_get_mem_data(output, &data);
        pem.assign(data, static_cast<size_t>(length));
    }
    BIO_free(output);
    sk_X509_EXTENSION_pop_free(extensions, X509_EXTENSION_free);
    X509_free(certificate);
    EVP_PKEY_free(issuer_key);
    EVP_PKEY_free(public_key);
    EVP_PKEY_CTX_free(key_context);
    X509_REQ_free(request);
    return pem;
}

std::string response_for(int status, std::string_view reason, std::string_view body,
                         std::string_view extra_headers = {}) {
    return "HTTP/1.1 " + std::to_string(status) + " " + std::string(reason) +
        "\r\nReplay-Nonce: next-nonce\r\n" + std::string(extra_headers) +
        "Content-Length: " + std::to_string(body.size()) +
        "\r\nConnection: close\r\n\r\n" + std::string(body);
}

void run_account_registration_test() {
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    assert(listener >= 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    assert(bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
    assert(listen(listener, 2) == 0);
    socklen_t address_size = sizeof(address);
    assert(getsockname(listener, reinterpret_cast<sockaddr*>(&address), &address_size) == 0);
    auto port = ntohs(address.sin_port);
    const auto origin = "http://127.0.0.1:" + std::to_string(port);
    std::string account_request;

    std::thread server([&] {
        for (int request_index = 0; request_index < 2; ++request_index) {
            int client = accept(listener, nullptr, nullptr);
            assert(client >= 0);
            std::string request;
            assert(receive_request(client, request));
            if (request_index == 0) {
                assert(request.starts_with("GET /directory "));
                const auto body = "{\"newNonce\":\"" + origin +
                    "/nonce\",\"newAccount\":\"" + origin +
                    "/new-account\",\"newOrder\":\"" + origin + "/new-order\"}";
                assert(send_response(client, "HTTP/1.1 200 OK\r\nReplay-Nonce: nonce-1\r\n"
                    "Content-Type: application/json\r\nContent-Length: " +
                    std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body));
            } else {
                assert(request.starts_with("POST /new-account "));
                account_request = request;
                const std::string body = "{}";
                assert(send_response(client, "HTTP/1.1 201 Created\r\nLocation: /account/1\r\n"
                    "Replay-Nonce: nonce-2\r\nContent-Length: " +
                    std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body));
            }
            shutdown(client, SHUT_RDWR);
            close(client);
        }
        close(listener);
    });

    char storage_template[] = "/tmp/justserver-acme-test-XXXXXX";
    char* storage = mkdtemp(storage_template);
    assert(storage);
    js::AcmeClient::Config config;
    config.directory_url = origin + "/directory";
    config.domains = {"example.test"};
    config.storage_path = storage;
    config.http.verify_tls = false;
    js::AcmeClient client(std::move(config));
    assert(client.initialize());
    server.join();

    struct stat key_stat{};
    assert(stat((std::string(storage) + "/account_key.pem").c_str(), &key_stat) == 0);
    assert((key_stat.st_mode & 0777) == 0600);

    auto separator = account_request.find("\r\n\r\n");
    assert(separator != std::string::npos);
    auto body = account_request.substr(separator + 4);
    auto protected_start = body.find("\"protected\":\"");
    auto payload_start = body.find("\"payload\":\"");
    auto signature_start = body.find("\"signature\":\"");
    assert(protected_start != std::string::npos && payload_start != std::string::npos &&
           signature_start != std::string::npos);
    protected_start += std::string("\"protected\":\"").size();
    payload_start += std::string("\"payload\":\"").size();
    signature_start += std::string("\"signature\":\"").size();
    auto protected_end = body.find('"', protected_start);
    auto payload_end = body.find('"', payload_start);
    auto signature_end = body.find('"', signature_start);
    assert(protected_end != std::string::npos && payload_end != std::string::npos &&
           signature_end != std::string::npos);
    auto protected_json = base64url_decode(
        std::string_view(body).substr(protected_start, protected_end - protected_start));
    auto payload_json = base64url_decode(
        std::string_view(body).substr(payload_start, payload_end - payload_start));
    auto signature = base64url_decode(
        std::string_view(body).substr(signature_start, signature_end - signature_start));
    assert(protected_json.find("\"alg\":\"ES256\"") != std::string::npos);
    assert(protected_json.find("\"nonce\":\"nonce-1\"") != std::string::npos);
    assert(protected_json.find("\"jwk\":") != std::string::npos);
    assert(payload_json == "{\"termsOfServiceAgreed\":true}");
    assert(signature.size() == 64);
    assert(verify_es256_jws(
        std::string_view(body).substr(protected_start, protected_end - protected_start),
        std::string_view(body).substr(payload_start, payload_end - payload_start),
        signature, protected_json));
    assert(client.handle_challenge("unknown-token") == std::nullopt);
    std::filesystem::remove_all(storage);
}

void run_full_order_test() {
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    assert(listener >= 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    assert(bind(listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0);
    assert(listen(listener, 12) == 0);
    socklen_t address_size = sizeof(address);
    assert(getsockname(listener, reinterpret_cast<sockaddr*>(&address), &address_size) == 0);
    auto port = ntohs(address.sin_port);
    const auto origin = "http://127.0.0.1:" + std::to_string(port);

    char storage_template[] = "/tmp/justserver-acme-flow-XXXXXX";
    char* storage = mkdtemp(storage_template);
    assert(storage);
    js::AcmeClient::Config config;
    config.directory_url = origin + "/directory";
    config.domains = {"example.test", "www.example.test"};
    config.storage_path = storage;
    config.authorization_timeout = std::chrono::seconds(5);
    config.poll_interval = std::chrono::seconds(1);
    js::AcmeClient client(std::move(config));
    std::string issued_certificate;

    std::thread server([&] {
        std::unordered_map<std::string, int> authorization_calls;
        for (int i = 0; i < 12; ++i) {
            int fd = accept(listener, nullptr, nullptr);
            assert(fd >= 0);
            std::string request;
            assert(receive_request(fd, request));
            auto line_end = request.find("\r\n");
            assert(line_end != std::string::npos);
            std::istringstream first_line(request.substr(0, line_end));
            std::string method, target;
            first_line >> method >> target;
            auto body_start = request.find("\r\n\r\n") + 4;
            auto request_body = std::string_view(request).substr(body_start);
            std::string response;
            if (target == "/directory") {
                auto body = "{\"newNonce\":\"" + origin + "/nonce\","
                    "\"newAccount\":\"" + origin + "/new-account\","
                    "\"newOrder\":\"" + origin + "/new-order\"}";
                response = response_for(200, "OK", body);
            } else if (target == "/new-account") {
                response = response_for(201, "Created", "{}", "Location: " +
                                        origin + "/account/1\r\n");
            } else if (target == "/new-order") {
                const auto order = "{\"status\":\"pending\","
                    "\"authorizations\":[\"" + origin + "/auth/one\",\"" + origin +
                    "/auth/two\"],\"finalize\":\"" + origin + "/finalize/1\"}";
                response = response_for(201, "Created", order,
                                        "Location: " + origin + "/order/1\r\n");
            } else if (target == "/auth/one" || target == "/auth/two") {
                if (authorization_calls[target]++ == 0) {
                    std::string number = target == "/auth/one" ? "one" : "two";
                    std::string domain = number == "one" ? "example.test" : "www.example.test";
                    std::string token = "token-" + number;
                    auto auth = "{\"status\":\"pending\",\"identifier\":{\"type\":\"dns\","
                        "\"value\":\"" + domain + "\"},\"challenges\":[{\"type\":\"http-01\","
                        "\"token\":\"" + token + "\",\"url\":\"" + origin +
                        "/challenge/" + number + "\"}]}";
                    response = response_for(200, "OK", auth);
                } else {
                    response = response_for(200, "OK", "{\"status\":\"valid\"}");
                }
            } else if (target == "/challenge/one" || target == "/challenge/two") {
                auto token = target == "/challenge/one" ? "token-one" : "token-two";
                auto authorization = client.handle_challenge(token);
                assert(authorization && authorization->starts_with(std::string(token) + "."));
                response = response_for(200, "OK", "{\"status\":\"processing\"}");
            } else if (target == "/finalize/1") {
                auto encoded_payload = json_string_field(request_body, "payload");
                auto payload = base64url_decode(encoded_payload);
                auto csr = base64url_decode(json_string_field(payload, "csr"));
                issued_certificate = certificate_for_csr(csr);
                assert(!issued_certificate.empty());
                response = response_for(200, "OK", "{\"status\":\"processing\"}");
            } else if (target == "/order/1") {
                response = response_for(200, "OK", "{\"status\":\"valid\",\"certificate\":\"" +
                                         origin + "/certificate\"}");
            } else if (target == "/certificate") {
                response = response_for(200, "OK", issued_certificate);
            } else {
                assert(false && "unexpected ACME endpoint");
            }
            auto nonce_position = response.find("next-nonce");
            assert(nonce_position != std::string::npos);
            response.replace(nonce_position, std::string("next-nonce").size(),
                             "nonce-" + std::to_string(i + 1));
            assert(send_response(fd, response));
            shutdown(fd, SHUT_RDWR);
            close(fd);
        }
        close(listener);
    });

    assert(client.initialize());
    assert(client.obtain_certificates());
    server.join();
    auto first = client.get_certificate("example.test");
    auto second = client.get_certificate("www.example.test");
    assert(first && first->valid && first->cert_pem == issued_certificate);
    assert(second && second->valid && second->cert_pem == issued_certificate);
    assert(std::filesystem::exists(std::filesystem::path(storage) /
                                   "example.test" / "key.pem"));
    std::filesystem::remove_all(storage);
}

void run_invalid_domain_test() {
    char storage_template[] = "/tmp/justserver-acme-invalid-XXXXXX";
    char* storage = mkdtemp(storage_template);
    assert(storage);
    js::AcmeClient::Config config;
    config.domains = {"-invalid.example"};
    config.storage_path = storage;
    js::AcmeClient client(std::move(config));
    assert(!client.initialize());
    std::filesystem::remove_all(storage);
}

} // namespace

void run_acme_tests() {
    run_account_registration_test();
    run_full_order_test();
    run_invalid_domain_test();
    std::cout << "  [PASS] ACME registration, HTTP-01 order, SAN certificate, and validation\n";
}
