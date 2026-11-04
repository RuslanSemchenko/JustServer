#include "anti_bot.hpp"
#include "tls_context.hpp"

#include <cassert>
#include <csignal>
#include <filesystem>
#include <iostream>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

namespace {

bool create_test_certificate(const std::filesystem::path& cert_path,
                             const std::filesystem::path& key_path) {
    EVP_PKEY_CTX* key_context = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
    EVP_PKEY* key = nullptr;
    bool ok = key_context && EVP_PKEY_keygen_init(key_context) > 0 &&
              EVP_PKEY_CTX_set_ec_paramgen_curve_nid(key_context, NID_X9_62_prime256v1) > 0 &&
              EVP_PKEY_keygen(key_context, &key) > 0;
    X509* certificate = ok ? X509_new() : nullptr;
    ok = ok && certificate && X509_set_version(certificate, 2) == 1 &&
         ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1) == 1 &&
         X509_gmtime_adj(X509_getm_notBefore(certificate), 0) != nullptr &&
         X509_gmtime_adj(X509_getm_notAfter(certificate), 3600) != nullptr &&
         X509_set_pubkey(certificate, key) == 1;
    X509_NAME* subject = certificate ? X509_get_subject_name(certificate) : nullptr;
    const unsigned char common_name[] = "localhost";
    ok = ok && subject &&
         X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, common_name, -1, -1, 0) == 1 &&
         X509_set_issuer_name(certificate, subject) == 1 &&
         X509_sign(certificate, key, EVP_sha256()) > 0;
    BIO* cert_file = ok ? BIO_new_file(cert_path.c_str(), "w") : nullptr;
    BIO* key_file = ok ? BIO_new_file(key_path.c_str(), "w") : nullptr;
    ok = ok && cert_file && key_file &&
         PEM_write_bio_X509(cert_file, certificate) == 1 &&
         PEM_write_bio_PrivateKey(key_file, key, nullptr, nullptr, 0, nullptr, nullptr) == 1;
    BIO_free(cert_file);
    BIO_free(key_file);
    X509_free(certificate);
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(key_context);
    return ok;
}

void test_client_hello_fingerprint() {
    signal(SIGPIPE, SIG_IGN);
    char directory_template[] = "/tmp/justserver-tls-test-XXXXXX";
    char* directory = mkdtemp(directory_template);
    assert(directory);
    auto cert_path = std::filesystem::path(directory) / "cert.pem";
    auto key_path = std::filesystem::path(directory) / "key.pem";
    assert(create_test_certificate(cert_path, key_path));

    js::TLSContext server_context;
    assert(server_context.init(cert_path.string(), key_path.string()));
    int sockets[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
    js::TlsFingerprinter::Fingerprint fingerprint;
    std::thread server([&] {
        SSL* ssl = server_context.wrap_socket(sockets[0]);
        assert(ssl);
        fingerprint = js::TlsFingerprinter::extract_ja3(ssl, "local-test");
        SSL_free(ssl);
        close(sockets[0]);
    });

    SSL_CTX* client_context = SSL_CTX_new(TLS_client_method());
    assert(client_context);
    SSL_CTX_set_verify(client_context, SSL_VERIFY_NONE, nullptr);
    SSL* client_ssl = SSL_new(client_context);
    assert(client_ssl);
    assert(SSL_set_fd(client_ssl, sockets[1]) == 1);
    assert(SSL_connect(client_ssl) == 1);
    SSL_free(client_ssl);
    SSL_CTX_free(client_context);
    close(sockets[1]);
    server.join();

    assert(fingerprint.client_ip == "local-test");
    assert(fingerprint.ja3_hash.size() == 32);
    auto first = fingerprint.ja3_raw.find(',');
    auto second = fingerprint.ja3_raw.find(',', first + 1);
    auto third = fingerprint.ja3_raw.find(',', second + 1);
    auto fourth = fingerprint.ja3_raw.find(',', third + 1);
    assert(first != std::string::npos && second != std::string::npos &&
           third != std::string::npos && fourth != std::string::npos);
    assert(second > first + 1);
    assert(third > second + 1);
    assert(fourth > third);

    std::filesystem::remove_all(directory);
}

} // namespace

void run_tls_tests() {
    test_client_hello_fingerprint();
    std::cout << "  [PASS] TLS ClientHello JA3 fingerprint capture\n";
}
