#include "http3.hpp"
#include "logger.hpp"

#include <ngtcp2/ngtcp2.h>
#include <ngtcp2/ngtcp2_crypto.h>
#include <ngtcp2/ngtcp2_crypto_gnutls.h>
#include <nghttp3/nghttp3.h>
#include <gnutls/gnutls.h>

#include <openssl/rand.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <algorithm>
#include <ctime>
#include <cctype>
#include <cstdlib>
#include <unordered_set>

// Helper: get current timestamp in nanoseconds for ngtcp2
static ngtcp2_tstamp get_timestamp_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<ngtcp2_tstamp>(ts.tv_sec) * 1000000000ULL +
           static_cast<ngtcp2_tstamp>(ts.tv_nsec);
}

namespace js {
namespace {

void quic_rand(uint8_t* dest, size_t destlen,
               [[maybe_unused]] const ngtcp2_rand_ctx* rand_ctx) {
    if (RAND_bytes(dest, static_cast<int>(destlen)) != 1) {
        std::abort();
    }
}

int quic_get_new_connection_id([[maybe_unused]] ngtcp2_conn* conn,
                               ngtcp2_cid* cid, uint8_t* token, size_t cidlen,
                               [[maybe_unused]] void* user_data) {
    if (cidlen > NGTCP2_MAX_CIDLEN ||
        RAND_bytes(cid->data, static_cast<int>(cidlen)) != 1 ||
        RAND_bytes(token, NGTCP2_STATELESS_RESET_TOKENLEN) != 1) {
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }
    cid->datalen = cidlen;
    return 0;
}

bool copy_socket_address(sockaddr_storage& destination, socklen_t& destination_len,
                         const sockaddr* source, socklen_t source_len) {
    if (!source || source_len == 0 || source_len > sizeof(destination)) return false;
    std::memcpy(&destination, source, source_len);
    destination_len = source_len;
    return true;
}

} // namespace

// === QuicConnectionId ===

bool QuicConnectionId::operator==(const QuicConnectionId& other) const {
    return len <= data.size() && other.len <= other.data.size() &&
           len == other.len && std::memcmp(data.data(), other.data.data(), len) == 0;
}

std::string QuicConnectionId::to_hex() const {
    if (len > data.size()) return {};
    std::string result;
    result.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", data[i]);
        result += buf;
    }
    return result;
}

QuicConnectionId QuicConnectionId::generate(size_t length) {
    QuicConnectionId cid;
    cid.len = (length > cid.data.size()) ? cid.data.size() : length;
    if (cid.len > 0 && RAND_bytes(cid.data.data(), static_cast<int>(cid.len)) != 1) {
        cid.len = 0;
    }
    return cid;
}

size_t QuicConnectionIdHash::operator()(const QuicConnectionId& cid) const {
    // FNV-1a hash over the CID bytes
    size_t h = 14695981039346656037ULL;
    if (cid.len > cid.data.size()) return h;
    for (size_t i = 0; i < cid.len; ++i) {
        h ^= cid.data[i];
        h *= 1099511628211ULL;
    }
    return h;
}

// === Helper: convert between ngtcp2_cid and QuicConnectionId ===

[[maybe_unused]] static QuicConnectionId from_ngtcp2_cid(const ngtcp2_cid* cid) {
    QuicConnectionId result;
    result.len = cid->datalen;
    if (result.len > result.data.size()) result.len = result.data.size();
    std::memcpy(result.data.data(), cid->data, result.len);
    return result;
}

[[maybe_unused]] static ngtcp2_cid to_ngtcp2_cid(const QuicConnectionId& cid) {
    ngtcp2_cid result;
    ngtcp2_cid_init(&result, cid.data.data(), cid.len);
    return result;
}

// === Http3Connection ===

Http3Connection::Http3Connection(RequestHandler handler, const QuicTransportParams& params,
                                 std::string client_ip)
    : handler_(std::move(handler)), params_(params), client_ip_(std::move(client_ip)) {

    conn_ref_ = std::make_unique<ngtcp2_crypto_conn_ref>();
    conn_ref_->get_conn = &Http3Connection::get_conn;
    conn_ref_->user_data = this;
}

Http3Connection::~Http3Connection() {
    if (h3_conn_) {
        nghttp3_conn_del(h3_conn_);
        h3_conn_ = nullptr;
    }
    if (quic_conn_) {
        ngtcp2_conn_del(quic_conn_);
        quic_conn_ = nullptr;
    }
    if (tls_session_) {
        gnutls_deinit(tls_session_);
        tls_session_ = nullptr;
    }
}

ngtcp2_conn* Http3Connection::get_conn(ngtcp2_crypto_conn_ref* conn_ref) {
    auto* self = static_cast<Http3Connection*>(conn_ref->user_data);
    return self->quic_conn_;
}

int Http3Connection::initialize(const QuicConnectionId& original_dcid,
                               const QuicConnectionId& client_scid,
                               uint32_t version, const sockaddr* local_addr,
                               socklen_t local_addr_len, const sockaddr* remote_addr,
                               socklen_t remote_addr_len,
                               gnutls_certificate_credentials_t credentials) {
    if (original_dcid.len == 0 || original_dcid.len > original_dcid.data.size() ||
        client_scid.len > client_scid.data.size() ||
        !copy_socket_address(local_address_, local_address_len_, local_addr, local_addr_len) ||
        !copy_socket_address(remote_address_, remote_address_len_, remote_addr, remote_addr_len)) {
        LOG_ERROR("HTTP/3: invalid QUIC connection address or connection ID");
        return -1;
    }

    scid_ = QuicConnectionId::generate(16);
    if (scid_.len != 16) {
        LOG_ERROR("HTTP/3: failed to generate server connection ID");
        return -1;
    }
    dcid_ = client_scid;

    if (gnutls_init(&tls_session_, GNUTLS_SERVER) != GNUTLS_E_SUCCESS) {
        LOG_ERROR("HTTP/3: failed to initialize GnuTLS session");
        return -1;
    }
    if (gnutls_priority_set_direct(tls_session_, "NORMAL:-VERS-ALL:+VERS-TLS1.3", nullptr) !=
            GNUTLS_E_SUCCESS ||
        gnutls_credentials_set(tls_session_, GNUTLS_CRD_CERTIFICATE, credentials) !=
            GNUTLS_E_SUCCESS) {
        LOG_ERROR("HTTP/3: failed to configure QUIC TLS session");
        return -1;
    }

    const gnutls_datum_t alpn{reinterpret_cast<unsigned char*>(const_cast<char*>("h3")), 2};
    if (gnutls_alpn_set_protocols(tls_session_, &alpn, 1,
                                  GNUTLS_ALPN_SERVER_PRECEDENCE) != GNUTLS_E_SUCCESS ||
        ngtcp2_crypto_gnutls_configure_server_session(tls_session_) != 0) {
        LOG_ERROR("HTTP/3: failed to configure QUIC TLS/ALPN");
        return -1;
    }
    gnutls_session_set_ptr(tls_session_, conn_ref_.get());

    ngtcp2_callbacks callbacks{};
    callbacks.recv_client_initial = ngtcp2_crypto_recv_client_initial_cb;
    callbacks.recv_crypto_data = ngtcp2_crypto_recv_crypto_data_cb;
    callbacks.handshake_completed = &Http3Connection::on_handshake_completed;
    callbacks.encrypt = ngtcp2_crypto_encrypt_cb;
    callbacks.decrypt = ngtcp2_crypto_decrypt_cb;
    callbacks.hp_mask = ngtcp2_crypto_hp_mask_cb;
    callbacks.recv_stream_data = &Http3Connection::on_recv_stream_data;
    callbacks.acked_stream_data_offset = &Http3Connection::on_acked_stream_data_offset;
    callbacks.stream_open = &Http3Connection::on_stream_open;
    callbacks.stream_close = &Http3Connection::on_stream_close;
    callbacks.rand = &quic_rand;
    callbacks.get_new_connection_id = &quic_get_new_connection_id;
    callbacks.delete_crypto_aead_ctx = ngtcp2_crypto_delete_crypto_aead_ctx_cb;
    callbacks.delete_crypto_cipher_ctx = ngtcp2_crypto_delete_crypto_cipher_ctx_cb;

    ngtcp2_settings settings;
    ngtcp2_settings_default(&settings);
    settings.initial_ts = get_timestamp_ns();
    settings.max_tx_udp_payload_size = params_.max_udp_payload_size;

    ngtcp2_transport_params transport_params;
    ngtcp2_transport_params_default(&transport_params);
    ngtcp2_cid original_cid = to_ngtcp2_cid(original_dcid);
    transport_params.original_dcid = original_cid;
    transport_params.original_dcid_present = 1;
    transport_params.initial_max_data = params_.initial_max_data;
    transport_params.initial_max_stream_data_bidi_local =
        params_.initial_max_stream_data_bidi_local;
    transport_params.initial_max_stream_data_bidi_remote =
        params_.initial_max_stream_data_bidi_remote;
    transport_params.initial_max_stream_data_uni = params_.initial_max_stream_data_uni;
    transport_params.initial_max_streams_bidi = params_.initial_max_streams_bidi;
    transport_params.initial_max_streams_uni = params_.initial_max_streams_uni;
    transport_params.max_idle_timeout = params_.max_idle_timeout_ms;
    transport_params.max_udp_payload_size = params_.max_udp_payload_size;
    transport_params.active_connection_id_limit = 2;
    if (params_.disable_active_migration) {
        transport_params.disable_active_migration = 1;
    }

    ngtcp2_path path{};
    path.local.addr = reinterpret_cast<ngtcp2_sockaddr*>(&local_address_);
    path.local.addrlen = local_address_len_;
    path.remote.addr = reinterpret_cast<ngtcp2_sockaddr*>(&remote_address_);
    path.remote.addrlen = remote_address_len_;
    path.user_data = this;

    auto dcid = to_ngtcp2_cid(original_dcid);
    auto scid = to_ngtcp2_cid(scid_);
    int rv = ngtcp2_conn_server_new(&quic_conn_, &dcid, &scid, &path, version,
                                    &callbacks, &settings, &transport_params,
                                    nullptr, this);
    if (rv != 0) {
        LOG_ERROR("HTTP/3: failed to create QUIC connection: " +
                  std::string(ngtcp2_strerror(rv)));
        return -1;
    }
    ngtcp2_conn_set_tls_native_handle(quic_conn_, tls_session_);

    LOG_DEBUG("HTTP/3 connection created: scid=" + scid_.to_hex());
    return 0;
}

int Http3Connection::on_handshake_completed(ngtcp2_conn* conn, void* user_data) {
    auto* self = static_cast<Http3Connection*>(user_data);
    nghttp3_callbacks callbacks{};
    callbacks.recv_header = &Http3Connection::on_h3_recv_header;
    callbacks.end_headers = &Http3Connection::on_h3_end_headers;
    callbacks.recv_data = &Http3Connection::on_h3_recv_data;
    callbacks.end_stream = &Http3Connection::on_h3_end_stream;

    nghttp3_settings settings;
    nghttp3_settings_default(&settings);
    int rv = nghttp3_conn_server_new(&self->h3_conn_, &callbacks, &settings,
                                     nullptr, self);
    if (rv != 0) {
        LOG_ERROR("HTTP/3: failed to create HTTP/3 connection: " +
                  std::string(nghttp3_strerror(rv)));
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    int64_t control_stream_id = -1;
    int64_t qpack_encoder_stream_id = -1;
    int64_t qpack_decoder_stream_id = -1;
    if (ngtcp2_conn_open_uni_stream(conn, &control_stream_id, nullptr) != 0 ||
        ngtcp2_conn_open_uni_stream(conn, &qpack_encoder_stream_id, nullptr) != 0 ||
        ngtcp2_conn_open_uni_stream(conn, &qpack_decoder_stream_id, nullptr) != 0 ||
        nghttp3_conn_bind_control_stream(self->h3_conn_, control_stream_id) != 0 ||
        nghttp3_conn_bind_qpack_streams(self->h3_conn_, qpack_encoder_stream_id,
                                        qpack_decoder_stream_id) != 0) {
        LOG_ERROR("HTTP/3: failed to open or bind HTTP/3 control streams");
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    self->handshake_complete_ = true;
    LOG_INFO("HTTP/3: QUIC handshake complete");
    return 0;
}

bool Http3Connection::is_alive() const {
    return alive_;
}

bool Http3Connection::is_handshake_complete() const {
    return handshake_complete_;
}

// === ngtcp2 callbacks ===

int Http3Connection::on_recv_stream_data([[maybe_unused]] ngtcp2_conn* conn,
                                           [[maybe_unused]] uint32_t flags,
                                           int64_t stream_id,
                                           [[maybe_unused]] uint64_t offset,
                                           const uint8_t* data, size_t datalen,
                                           void* user_data,
                                           [[maybe_unused]] void* stream_user_data) {
    auto* self = static_cast<Http3Connection*>(user_data);
    if (!self->h3_conn_) return 0;

    // Feed data to nghttp3
    auto nconsumed = nghttp3_conn_read_stream(self->h3_conn_, stream_id, data, datalen,
                                               (flags & NGTCP2_STREAM_DATA_FLAG_FIN) != 0);
    if (nconsumed < 0) {
        LOG_ERROR("HTTP/3: nghttp3_conn_read_stream failed: " +
                  std::string(nghttp3_strerror(static_cast<int>(nconsumed))));
        return NGTCP2_ERR_CALLBACK_FAILURE;
    }

    ngtcp2_conn_extend_max_stream_offset(conn, stream_id, static_cast<uint64_t>(nconsumed));
    ngtcp2_conn_extend_max_offset(conn, static_cast<uint64_t>(nconsumed));

    return 0;
}

int Http3Connection::on_stream_open([[maybe_unused]] ngtcp2_conn* conn,
                                      int64_t stream_id, void* user_data) {
    auto* self = static_cast<Http3Connection*>(user_data);
    self->streams_[stream_id] = StreamContext{};
    ++self->streams_opened_;
    LOG_DEBUG("HTTP/3 stream opened: " + std::to_string(stream_id));
    return 0;
}

int Http3Connection::on_stream_close([[maybe_unused]] ngtcp2_conn* conn,
                                       [[maybe_unused]] uint32_t flags,
                                       int64_t stream_id,
                                       [[maybe_unused]] uint64_t app_error_code,
                                       void* user_data,
                                       [[maybe_unused]] void* stream_user_data) {
    auto* self = static_cast<Http3Connection*>(user_data);

    if (self->h3_conn_) {
        nghttp3_conn_close_stream(self->h3_conn_, stream_id, app_error_code);
    }

    self->streams_.erase(stream_id);
    self->response_bodies_.erase(stream_id);
    LOG_DEBUG("HTTP/3 stream closed: " + std::to_string(stream_id));
    return 0;
}

int Http3Connection::on_acked_stream_data_offset([[maybe_unused]] ngtcp2_conn* conn,
                                                    int64_t stream_id,
                                                    uint64_t offset, uint64_t datalen,
                                                    void* user_data,
                                                    [[maybe_unused]] void* stream_user_data) {
    auto* self = static_cast<Http3Connection*>(user_data);
    if (self->h3_conn_) {
        nghttp3_conn_add_ack_offset(self->h3_conn_, stream_id, datalen);
        (void)offset;
    }
    return 0;
}

// === nghttp3 callbacks ===

int Http3Connection::on_h3_recv_header([[maybe_unused]] nghttp3_conn* conn,
                                         int64_t stream_id,
                                         [[maybe_unused]] int32_t token,
                                         nghttp3_rcbuf* name, nghttp3_rcbuf* value,
                                         [[maybe_unused]] uint8_t flags,
                                         void* user_data,
                                         [[maybe_unused]] void* stream_user_data) {
    auto* self = static_cast<Http3Connection*>(user_data);
    auto it = self->streams_.find(stream_id);
    if (it == self->streams_.end()) return 0;

    auto name_vec = nghttp3_rcbuf_get_buf(name);
    auto value_vec = nghttp3_rcbuf_get_buf(value);
    std::string header_name(reinterpret_cast<const char*>(name_vec.base), name_vec.len);
    std::string header_value(reinterpret_cast<const char*>(value_vec.base), value_vec.len);

    auto& req = it->second.request;

    // Pseudo-headers
    if (header_name == ":method") {
        req.method_str = header_value;
        if (header_value == "GET") req.method = HttpMethod::GET;
        else if (header_value == "POST") req.method = HttpMethod::POST;
        else if (header_value == "PUT") req.method = HttpMethod::PUT;
        else if (header_value == "DELETE") req.method = HttpMethod::DELETE_;
        else if (header_value == "HEAD") req.method = HttpMethod::HEAD;
        else if (header_value == "OPTIONS") req.method = HttpMethod::OPTIONS;
        else if (header_value == "PATCH") req.method = HttpMethod::PATCH;
    } else if (header_name == ":path") {
        req.uri = header_value;
        req.path = header_value;
        auto q = req.path.find('?');
        if (q != std::string::npos) {
            req.query_string = req.path.substr(q + 1);
            req.path = req.path.substr(0, q);
        }
    } else if (header_name == ":scheme") {
        // Store but don't need to act on it
    } else if (header_name == ":authority") {
        req.headers["Host"] = header_value;
    } else {
        req.headers[header_name] = header_value;
    }

    return 0;
}

int Http3Connection::on_h3_end_headers([[maybe_unused]] nghttp3_conn* conn,
                                         int64_t stream_id,
                                         [[maybe_unused]] int token,
                                         void* user_data,
                                         [[maybe_unused]] void* stream_user_data) {
    auto* self = static_cast<Http3Connection*>(user_data);
    auto it = self->streams_.find(stream_id);
    if (it != self->streams_.end()) {
        it->second.headers_complete = true;
        it->second.request.version = "HTTP/3";
    }
    return 0;
}

int Http3Connection::on_h3_recv_data([[maybe_unused]] nghttp3_conn* conn,
                                       int64_t stream_id,
                                       const uint8_t* data, size_t datalen,
                                       void* user_data,
                                       [[maybe_unused]] void* stream_user_data) {
    auto* self = static_cast<Http3Connection*>(user_data);
    auto it = self->streams_.find(stream_id);
    if (it != self->streams_.end()) {
        if (it->second.response_submitted) return 0;
        const auto current_size = it->second.request.body.size();
        if (datalen > self->params_.max_request_size_bytes ||
            current_size > self->params_.max_request_size_bytes - datalen) {
            it->second.response_submitted = true;
            self->send_response(stream_id, HttpResponse::make_error(413, "Request body too large"));
            if (ngtcp2_conn_shutdown_stream_read(self->quic_conn_, 0, stream_id,
                                                 NGHTTP3_H3_EXCESSIVE_LOAD) != 0) {
                LOG_WARN("HTTP/3: failed to stop oversized request body");
            }
            return 0;
        }
        it->second.request.body.append(reinterpret_cast<const char*>(data), datalen);
    }
    return 0;
}

int Http3Connection::on_h3_end_stream([[maybe_unused]] nghttp3_conn* conn,
                                        int64_t stream_id,
                                        void* user_data,
                                        [[maybe_unused]] void* stream_user_data) {
    auto* self = static_cast<Http3Connection*>(user_data);
    auto it = self->streams_.find(stream_id);
    if (it == self->streams_.end()) return 0;
    if (it->second.response_submitted) return 0;

    it->second.data_complete = true;

    // Process the complete request through the handler
    auto& req = it->second.request;
    LOG_INFO("HTTP/3 " + req.method_str + " " + req.uri);

    auto resp = self->handler_(req, self->client_ip_);
    self->send_response(stream_id, resp);
    it->second.response_submitted = true;

    return 0;
}

// === Response sending ===

void Http3Connection::send_response(int64_t stream_id, const HttpResponse& resp) {
    if (!h3_conn_) return;

    std::string status_str = std::to_string(resp.status_code);
    std::vector<nghttp3_nv> nvs;
    nvs.reserve(resp.headers.size() + 2);
    std::vector<std::string> storage;
    storage.reserve((resp.headers.size() + 2) * 2);

    auto add_header = [&](std::string_view name, std::string_view value) {
        storage.emplace_back(name);
        storage.emplace_back(value);
        size_t idx = storage.size();
        nghttp3_nv nv;
        nv.name = reinterpret_cast<uint8_t*>(storage[idx - 2].data());
        nv.namelen = storage[idx - 2].size();
        nv.value = reinterpret_cast<uint8_t*>(storage[idx - 1].data());
        nv.valuelen = storage[idx - 1].size();
        nv.flags = NGHTTP3_NV_FLAG_NONE;
        nvs.push_back(nv);
    };

    add_header(":status", status_str);
    bool has_content_length = false;
    bool body_allowed = resp.status_code >= 200 && resp.status_code != 204 &&
                        resp.status_code != 304;
    auto request = streams_.find(stream_id);
    if (request != streams_.end() && request->second.request.method == HttpMethod::HEAD) {
        body_allowed = false;
    }
    std::string response_body = body_allowed ? resp.body : std::string{};
    auto is_hop_by_hop = [](std::string_view name) {
        return name == "connection" || name == "keep-alive" ||
               name == "proxy-connection" || name == "transfer-encoding" ||
               name == "upgrade";
    };
    for (const auto& [key, value] : resp.headers) {
        std::string lower_name = key;
        std::transform(lower_name.begin(), lower_name.end(), lower_name.begin(),
                       [](unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
        if (lower_name.empty() || lower_name.front() == ':' || is_hop_by_hop(lower_name) ||
            (lower_name == "te" && value != "trailers"))
            continue;
        if (lower_name == "content-length") has_content_length = true;
        add_header(lower_name, value);
    }
    if (!has_content_length) {
        add_header("content-length", std::to_string(response_body.size()));
    }

    nghttp3_data_reader dr{};
    ResponseBody* body_context = nullptr;
    if (!response_body.empty()) {
        auto body = std::make_unique<ResponseBody>();
        body->data = std::move(response_body);
        body_context = body.get();
        response_bodies_[stream_id] = std::move(body);
        dr.read_data = [](nghttp3_conn*, int64_t, nghttp3_vec* vec,
                          size_t veccnt, uint32_t* pflags,
                          void*, void* stream_user_data) -> nghttp3_ssize {
            auto* ctx = static_cast<ResponseBody*>(stream_user_data);
            if (!ctx) return NGHTTP3_ERR_CALLBACK_FAILURE;
            if (ctx->offset >= ctx->data.size()) {
                *pflags = NGHTTP3_DATA_FLAG_EOF;
                return 0;
            }
            if (veccnt == 0) return 0;
            vec[0].base = reinterpret_cast<uint8_t*>(ctx->data.data() + ctx->offset);
            vec[0].len = ctx->data.size() - ctx->offset;
            ctx->offset = ctx->data.size();
            *pflags = NGHTTP3_DATA_FLAG_EOF;
            return 1;
        };
    }

    int rv = nghttp3_conn_submit_response(h3_conn_, stream_id, nvs.data(), nvs.size(),
                                           body_context ? &dr : nullptr);
    if (rv != 0) {
        response_bodies_.erase(stream_id);
        LOG_ERROR("HTTP/3: failed to submit response: " + std::string(nghttp3_strerror(rv)));
        return;
    }
    if (body_context && nghttp3_conn_set_stream_user_data(h3_conn_, stream_id, body_context) != 0) {
        response_bodies_.erase(stream_id);
        nghttp3_conn_shutdown_stream_read(h3_conn_, stream_id);
        nghttp3_conn_shutdown_stream_write(h3_conn_, stream_id);
        LOG_ERROR("HTTP/3: failed to attach response body to stream");
    }
}

// === Packet I/O ===

std::vector<Http3Connection::OutgoingPacket>
Http3Connection::process_input(std::span<const uint8_t> data,
                               const sockaddr* local_addr, socklen_t local_addr_len,
                               const sockaddr* remote_addr, socklen_t remote_addr_len) {
    if (!quic_conn_) return {};

    sockaddr_storage local_storage{};
    sockaddr_storage remote_storage{};
    socklen_t local_length = 0;
    socklen_t remote_length = 0;
    if (!copy_socket_address(local_storage, local_length, local_addr, local_addr_len) ||
        !copy_socket_address(remote_storage, remote_length, remote_addr, remote_addr_len)) {
        LOG_WARN("HTTP/3: received packet with invalid socket address");
        return {};
    }

    bytes_received_ += data.size();

    ngtcp2_path_storage path;
    ngtcp2_path_storage_init(
        &path, reinterpret_cast<ngtcp2_sockaddr*>(&local_storage), local_length,
        reinterpret_cast<ngtcp2_sockaddr*>(&remote_storage), remote_length, this);

    ngtcp2_pkt_info pi{};
    auto ts = get_timestamp_ns();

    int rv = ngtcp2_conn_read_pkt(quic_conn_, &path.path, &pi,
                                   data.data(), data.size(), ts);
    if (rv != 0) {
        if (rv == NGTCP2_ERR_DRAINING || rv == NGTCP2_ERR_CLOSING) {
            alive_ = false;
        } else {
            LOG_WARN("HTTP/3: ngtcp2_conn_read_pkt error: " +
                     std::string(ngtcp2_strerror(rv)));
        }
    }

    return write_packets();
}

std::vector<Http3Connection::OutgoingPacket> Http3Connection::write_packets() {
    std::vector<OutgoingPacket> packets;
    if (!quic_conn_) return packets;

    auto ts = get_timestamp_ns();
    std::array<uint8_t, 1350> buf{};

    for (;;) {
        ngtcp2_path_storage ps;
        ngtcp2_path_storage_init(
            &ps, reinterpret_cast<ngtcp2_sockaddr*>(&local_address_), local_address_len_,
            reinterpret_cast<ngtcp2_sockaddr*>(&remote_address_), remote_address_len_, this);
        ngtcp2_pkt_info pi{};

        // Write QUIC packets
        ngtcp2_ssize n;

        // Check if nghttp3 has data to send
        int64_t stream_id = -1;
        nghttp3_vec vec[16]{};
        nghttp3_ssize sveccnt = 0;
        int fin = 0;

        if (h3_conn_) {
            sveccnt = nghttp3_conn_writev_stream(h3_conn_, &stream_id,
                                                  &fin, vec, 16);
            if (sveccnt < 0) {
                sveccnt = 0;
                stream_id = -1;
            }
        }

        if (stream_id >= 0 && sveccnt > 0) {
            // Write stream data
            ngtcp2_vec nv[16];
            for (nghttp3_ssize i = 0; i < sveccnt; ++i) {
                nv[i].base = vec[i].base;
                nv[i].len = vec[i].len;
            }

            ngtcp2_ssize ndatalen;
            uint32_t flags = NGTCP2_WRITE_STREAM_FLAG_MORE;
            if (fin) flags |= NGTCP2_WRITE_STREAM_FLAG_FIN;

            n = ngtcp2_conn_writev_stream(quic_conn_, &ps.path, &pi,
                                           buf.data(), buf.size(),
                                           &ndatalen, flags,
                                           stream_id, nv,
                                           static_cast<size_t>(sveccnt), ts);

            if (n > 0 && ndatalen >= 0 && h3_conn_) {
                nghttp3_conn_add_write_offset(h3_conn_, stream_id,
                                               static_cast<uint64_t>(ndatalen));
            }
        } else {
            // Write QUIC control frames only
            n = ngtcp2_conn_write_pkt(quic_conn_, &ps.path, &pi,
                                       buf.data(), buf.size(), ts);
        }

        if (n < 0) {
            if (n == NGTCP2_ERR_WRITE_MORE) continue;
            break;
        }
        if (n == 0) break;

        OutgoingPacket pkt;
        pkt.data.assign(buf.begin(), buf.begin() + n);
        pkt.destination = remote_address_;
        pkt.address_length = remote_address_len_;
        bytes_sent_ += static_cast<uint64_t>(n);
        packets.push_back(std::move(pkt));
    }

    return packets;
}

std::vector<QuicConnectionId> Http3Connection::source_connection_ids() const {
    std::vector<QuicConnectionId> result;
    if (!quic_conn_) return result;

    size_t count = ngtcp2_conn_get_scid(quic_conn_, nullptr);
    std::vector<ngtcp2_cid> cids(count);
    if (count != 0) {
        count = ngtcp2_conn_get_scid(quic_conn_, cids.data());
        result.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            QuicConnectionId cid;
            cid.len = cids[i].datalen;
            if (cid.len > 0 && cid.len <= cid.data.size()) {
                std::memcpy(cid.data.data(), cids[i].data, cid.len);
                result.push_back(cid);
            }
        }
    }
    return result;
}

std::vector<Http3Connection::OutgoingPacket> Http3Connection::on_timer() {
    if (!quic_conn_) return {};

    auto ts = get_timestamp_ns();
    if (ngtcp2_conn_get_expiry(quic_conn_) > ts) return {};
    int rv = ngtcp2_conn_handle_expiry(quic_conn_, ts);
    if (rv != 0) {
        LOG_WARN("HTTP/3: handle_expiry error: " + std::string(ngtcp2_strerror(rv)));
        alive_ = false;
        return {};
    }

    return write_packets();
}

int Http3Connection::set_credentials(gnutls_certificate_credentials_t credentials) {
    if (!tls_session_) return 0;
    return gnutls_credentials_set(tls_session_, GNUTLS_CRD_CERTIFICATE, credentials);
}

std::chrono::milliseconds Http3Connection::next_timeout() const {
    if (!quic_conn_) return std::chrono::milliseconds(100);

    auto expiry = ngtcp2_conn_get_expiry(quic_conn_);
    auto now = get_timestamp_ns();

    if (expiry <= now) return std::chrono::milliseconds(0);

    auto diff = expiry - now;
    // ngtcp2 timestamps are in nanoseconds
    return std::chrono::milliseconds(static_cast<int64_t>(diff / 1000000));
}

// === QuicDispatcher ===

std::optional<QuicDispatcher::DecodedPacket> QuicDispatcher::decode_packet(
    std::span<const uint8_t> data, size_t short_dcid_length) {
    if (data.empty()) return std::nullopt;
    ngtcp2_version_cid version_cid{};
    int rv = ngtcp2_pkt_decode_version_cid(
        &version_cid, data.data(), data.size(), short_dcid_length);
    if (rv != 0 && rv != NGTCP2_ERR_VERSION_NEGOTIATION) return std::nullopt;
    if (version_cid.dcidlen > QuicConnectionId{}.data.size() ||
        version_cid.scidlen > QuicConnectionId{}.data.size()) {
        return std::nullopt;
    }

    DecodedPacket result;
    result.version = version_cid.version;
    result.dcid.len = version_cid.dcidlen;
    if (result.dcid.len > 0) {
        std::memcpy(result.dcid.data.data(), version_cid.dcid, result.dcid.len);
    }
    result.scid.len = version_cid.scidlen;
    if (result.scid.len > 0) {
        std::memcpy(result.scid.data.data(), version_cid.scid, result.scid.len);
    }

    if ((data[0] & NGTCP2_PKT_FLAG_LONG_FORM) != 0) {
        ngtcp2_pkt_hd header{};
        auto header_length = ngtcp2_pkt_decode_hd_long(
            &header, data.data(), data.size());
        if (header_length < 0) return std::nullopt;
        result.initial = header.type == NGTCP2_PKT_INITIAL;
    }
    return result;
}

QuicDispatcher::QuicDispatcher(Config config, Http3Connection::RequestHandler handler)
    : config_(std::move(config)), handler_(std::move(handler)) {}

QuicDispatcher::~QuicDispatcher() {
    if (udp_fd_ >= 0) {
        close(udp_fd_);
    }
    connections_.clear();
    cid_routes_.clear();
    if (tls_credentials_) {
        gnutls_certificate_free_credentials(tls_credentials_);
        tls_credentials_ = nullptr;
    }
}

bool QuicDispatcher::init() {
    if (udp_fd_ >= 0) return true;

    if (config_.tls_cert_path.empty() || config_.tls_key_path.empty()) {
        LOG_ERROR("HTTP/3: TLS certificate and key paths are required");
        return false;
    }
    int tls_rv = gnutls_certificate_allocate_credentials(&tls_credentials_);
    if (tls_rv != GNUTLS_E_SUCCESS) {
        LOG_ERROR("HTTP/3: failed to allocate TLS credentials: " +
                  std::string(gnutls_strerror(tls_rv)));
        return false;
    }
    tls_rv = gnutls_certificate_set_x509_key_file(
        tls_credentials_, config_.tls_cert_path.c_str(), config_.tls_key_path.c_str(),
        GNUTLS_X509_FMT_PEM);
    if (tls_rv != GNUTLS_E_SUCCESS) {
        LOG_ERROR("HTTP/3: failed to load TLS certificate/key: " +
                  std::string(gnutls_strerror(tls_rv)));
        gnutls_certificate_free_credentials(tls_credentials_);
        tls_credentials_ = nullptr;
        return false;
    }

    udp_fd_ = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (udp_fd_ < 0) {
        LOG_ERROR("HTTP/3: Failed to create UDP socket: " + std::string(strerror(errno)));
        gnutls_certificate_free_credentials(tls_credentials_);
        tls_credentials_ = nullptr;
        return false;
    }

    // Allow address reuse
    int opt = 1;
    setsockopt(udp_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(udp_fd_, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));

    // Set receive buffer size (larger for QUIC)
    int rcvbuf = 2 * 1024 * 1024; // 2 MB
    setsockopt(udp_fd_, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    // Bind
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config_.port);
    if (inet_pton(AF_INET, config_.bind_address.c_str(), &addr.sin_addr) <= 0) {
        LOG_ERROR("HTTP/3: Invalid bind address: " + config_.bind_address);
        close(udp_fd_);
        udp_fd_ = -1;
        gnutls_certificate_free_credentials(tls_credentials_);
        tls_credentials_ = nullptr;
        return false;
    }

    if (bind(udp_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        LOG_ERROR("HTTP/3: Failed to bind UDP: " + std::string(strerror(errno)));
        close(udp_fd_);
        udp_fd_ = -1;
        gnutls_certificate_free_credentials(tls_credentials_);
        tls_credentials_ = nullptr;
        return false;
    }

    LOG_INFO("HTTP/3: UDP listener on " + config_.bind_address + ":" +
             std::to_string(config_.port));
    return true;
}

bool QuicDispatcher::reload_tls_credentials() {
    gnutls_certificate_credentials_t updated_credentials = nullptr;
    int rv = gnutls_certificate_allocate_credentials(&updated_credentials);
    if (rv != GNUTLS_E_SUCCESS) {
        LOG_ERROR("HTTP/3: failed to allocate replacement TLS credentials: " +
                  std::string(gnutls_strerror(rv)));
        return false;
    }
    rv = gnutls_certificate_set_x509_key_file(
        updated_credentials, config_.tls_cert_path.c_str(), config_.tls_key_path.c_str(),
        GNUTLS_X509_FMT_PEM);
    if (rv != GNUTLS_E_SUCCESS) {
        LOG_ERROR("HTTP/3: failed to load replacement TLS certificate/key: " +
                  std::string(gnutls_strerror(rv)));
        gnutls_certificate_free_credentials(updated_credentials);
        return false;
    }

    std::lock_guard lock(connections_mutex_);
    std::vector<Http3Connection*> updated_connections;
    for (auto& [cid, conn] : connections_) {
        (void)cid;
        rv = conn->set_credentials(updated_credentials);
        if (rv != GNUTLS_E_SUCCESS) {
            for (auto* updated_conn : updated_connections) {
                if (updated_conn->set_credentials(tls_credentials_) != GNUTLS_E_SUCCESS) {
                    LOG_ERROR("HTTP/3: failed to restore old TLS credentials after reload error");
                }
            }
            LOG_ERROR("HTTP/3: failed to update connection TLS credentials: " +
                      std::string(gnutls_strerror(rv)));
            gnutls_certificate_free_credentials(updated_credentials);
            return false;
        }
        updated_connections.push_back(conn.get());
    }

    auto old_credentials = tls_credentials_;
    tls_credentials_ = updated_credentials;
    if (old_credentials) gnutls_certificate_free_credentials(old_credentials);
    return true;
}

int QuicDispatcher::process_packets() {
    if (udp_fd_ < 0) return 0;

    int count = 0;
    std::array<uint8_t, 65536> buf{};
    sockaddr_storage peer_addr{};
    sockaddr_storage local_addr{};
    socklen_t local_len = sizeof(local_addr);
    if (getsockname(udp_fd_, reinterpret_cast<sockaddr*>(&local_addr), &local_len) < 0) {
        LOG_ERROR("HTTP/3: getsockname failed: " + std::string(strerror(errno)));
        return 0;
    }

    for (int i = 0; i < 64; ++i) { // Process up to 64 packets per call
        socklen_t peer_len = sizeof(peer_addr);
        auto n = recvfrom(udp_fd_, buf.data(), buf.size(), 0,
                           reinterpret_cast<sockaddr*>(&peer_addr), &peer_len);

        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            LOG_WARN("HTTP/3: recvfrom error: " + std::string(strerror(errno)));
            break;
        }

        ++total_packets_rx_;
        ++count;

        // Get peer address string
        char ip_buf[INET6_ADDRSTRLEN]{};
        std::string peer_ip = "unknown";
        if (peer_addr.ss_family == AF_INET) {
            const auto* address = reinterpret_cast<const sockaddr_in*>(&peer_addr);
            if (inet_ntop(AF_INET, &address->sin_addr, ip_buf, sizeof(ip_buf))) {
                peer_ip = ip_buf;
            }
        } else if (peer_addr.ss_family == AF_INET6) {
            const auto* address = reinterpret_cast<const sockaddr_in6*>(&peer_addr);
            if (inet_ntop(AF_INET6, &address->sin6_addr, ip_buf, sizeof(ip_buf))) {
                peer_ip = ip_buf;
            }
        }

        auto packet_cids = decode_packet(
            std::span<const uint8_t>(buf.data(), static_cast<size_t>(n)));
        if (!packet_cids) continue;

        // Find or create connection
        std::lock_guard lock(connections_mutex_);
        auto* conn = find_connection(packet_cids->dcid);

        if (!conn) {
            // New connection (must be an Initial packet)
            if (packet_cids->initial) {
                conn = create_connection(packet_cids->scid, packet_cids->dcid,
                                         packet_cids->version,
                                         reinterpret_cast<const sockaddr*>(&local_addr),
                                         local_len,
                                         reinterpret_cast<const sockaddr*>(&peer_addr),
                                         peer_len, peer_ip);
            }

            if (!conn) continue;
        }

        // Feed packet to connection
        auto replies = conn->process_input(
            std::span<const uint8_t>(buf.data(), static_cast<size_t>(n)),
            reinterpret_cast<const sockaddr*>(&local_addr), local_len,
            reinterpret_cast<const sockaddr*>(&peer_addr), peer_len);
        register_connection_ids(conn);

        // Send replies
        for (const auto& reply : replies) {
            auto sent = sendto(udp_fd_, reply.data.data(), reply.data.size(), 0,
                               reinterpret_cast<const sockaddr*>(&reply.destination),
                               reply.address_length);
            if (sent < 0 || static_cast<size_t>(sent) != reply.data.size()) {
                LOG_WARN("HTTP/3: failed to send QUIC reply: " +
                         std::string(strerror(errno)));
            } else {
                ++total_packets_tx_;
            }
        }
    }

    return count;
}

int QuicDispatcher::flush_output() {
    if (udp_fd_ < 0) return 0;

    // Iterate all connections and flush any pending output
    std::lock_guard lock(connections_mutex_);
    int count = 0;

    for (auto& [cid, conn] : connections_) {
        (void)cid;
        auto packets = conn->on_timer();
        for (const auto& packet : packets) {
            auto sent = sendto(udp_fd_, packet.data.data(), packet.data.size(), 0,
                               reinterpret_cast<const sockaddr*>(&packet.destination),
                               packet.address_length);
            if (sent < 0 || static_cast<size_t>(sent) != packet.data.size()) {
                LOG_WARN("HTTP/3: failed to send timer packet: " +
                         std::string(strerror(errno)));
            } else {
                ++total_packets_tx_;
                ++count;
            }
        }
    }

    return count;
}

void QuicDispatcher::tick() {
    cleanup_idle();
}

size_t QuicDispatcher::active_connections() const {
    std::lock_guard lock(connections_mutex_);
    return connections_.size();
}

Http3Connection* QuicDispatcher::find_connection(const QuicConnectionId& dcid) {
    auto it = cid_routes_.find(dcid);
    return it == cid_routes_.end() ? nullptr : it->second;
}

Http3Connection* QuicDispatcher::create_connection(const QuicConnectionId& scid,
                                                      const QuicConnectionId& dcid,
                                                      uint32_t version,
                                                      const sockaddr* local_addr,
                                                      socklen_t local_addr_len,
                                                      const sockaddr* remote_addr,
                                                      socklen_t remote_addr_len,
                                                      const std::string& peer_addr) {
    if (connections_.size() >= config_.max_connections) {
        LOG_WARN("HTTP/3: Max connections reached, rejecting " + peer_addr);
        return nullptr;
    }

    auto conn = std::make_unique<Http3Connection>(handler_, config_.transport_params,
                                                  peer_addr);
    auto* ptr = conn.get();
    if (ptr->initialize(dcid, scid, version, local_addr, local_addr_len,
                        remote_addr, remote_addr_len, tls_credentials_) != 0) {
        LOG_WARN("HTTP/3: failed to initialize connection from " + peer_addr);
        return nullptr;
    }

    // Keep ownership keyed by the original destination CID from the Initial.
    connections_[dcid] = std::move(conn);
    cid_routes_[dcid] = ptr;
    register_connection_ids(ptr);

    LOG_INFO("HTTP/3: New connection from " + peer_addr +
             " scid=" + scid.to_hex() + " dcid=" + dcid.to_hex());

    return ptr;
}

void QuicDispatcher::remove_connection(const QuicConnectionId& cid) {
    auto connection = connections_.find(cid);
    if (connection == connections_.end()) return;
    auto* ptr = connection->second.get();
    for (auto route = cid_routes_.begin(); route != cid_routes_.end();) {
        if (route->second == ptr) {
            route = cid_routes_.erase(route);
        } else {
            ++route;
        }
    }
    connections_.erase(connection);
}

void QuicDispatcher::register_connection_ids(Http3Connection* conn) {
    auto source_cids = conn->source_connection_ids();
    std::unordered_set<QuicConnectionId, QuicConnectionIdHash> active_cids(
        source_cids.begin(), source_cids.end());
    for (const auto& [owner_cid, owned_conn] : connections_) {
        if (owned_conn.get() == conn) {
            active_cids.insert(owner_cid);
            break;
        }
    }

    for (auto route = cid_routes_.begin(); route != cid_routes_.end();) {
        if (route->second == conn && !active_cids.contains(route->first)) {
            route = cid_routes_.erase(route);
        } else {
            ++route;
        }
    }
    for (const auto& cid : source_cids) {
        cid_routes_[cid] = conn;
    }
}

void QuicDispatcher::cleanup_idle() {
    std::lock_guard lock(connections_mutex_);

    for (auto it = connections_.begin(); it != connections_.end(); ) {
        if (!it->second->is_alive()) {
            LOG_DEBUG("HTTP/3: Cleaning up dead connection " + it->first.to_hex());
            auto* ptr = it->second.get();
            for (auto route = cid_routes_.begin(); route != cid_routes_.end();) {
                if (route->second == ptr) {
                    route = cid_routes_.erase(route);
                } else {
                    ++route;
                }
            }
            it = connections_.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace js
