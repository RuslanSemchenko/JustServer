#include "http3.hpp"
#include "logger.hpp"

#include <ngtcp2/ngtcp2.h>
#include <nghttp3/nghttp3.h>

#include <openssl/rand.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <algorithm>
#include <ctime>

// Helper: get current timestamp in nanoseconds for ngtcp2
static ngtcp2_tstamp get_timestamp_ns() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<ngtcp2_tstamp>(ts.tv_sec) * 1000000000ULL +
           static_cast<ngtcp2_tstamp>(ts.tv_nsec);
}

namespace js {

// === QuicConnectionId ===

bool QuicConnectionId::operator==(const QuicConnectionId& other) const {
    return len == other.len && std::memcmp(data.data(), other.data.data(), len) == 0;
}

std::string QuicConnectionId::to_hex() const {
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
    RAND_bytes(cid.data.data(), static_cast<int>(cid.len));
    return cid;
}

size_t QuicConnectionIdHash::operator()(const QuicConnectionId& cid) const {
    // FNV-1a hash over the CID bytes
    size_t h = 14695981039346656037ULL;
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

Http3Connection::Http3Connection(RequestHandler handler, const QuicTransportParams& params)
    : handler_(std::move(handler)), params_(params) {

    scid_ = QuicConnectionId::generate(16);
    dcid_ = QuicConnectionId::generate(16);

    LOG_DEBUG("HTTP/3 connection created: scid=" + scid_.to_hex());
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

    it->second.data_complete = true;

    // Process the complete request through the handler
    auto& req = it->second.request;
    LOG_INFO("HTTP/3 " + req.method_str + " " + req.uri);

    auto resp = self->handler_(req);
    self->send_response(stream_id, resp);

    return 0;
}

// === Response sending ===

void Http3Connection::send_response(int64_t stream_id, const HttpResponse& resp) {
    if (!h3_conn_) return;

    // Build nghttp3 name-value pairs for response headers
    std::string status_str = std::to_string(resp.status_code);

    // We need to keep the header data alive until nghttp3 consumes it
    struct HeaderData {
        std::vector<nghttp3_nv> nvs;
        std::vector<std::string> storage; // Keep strings alive
    };
    auto hd = std::make_shared<HeaderData>();

    auto add_header = [&](std::string_view name, std::string_view value) {
        hd->storage.emplace_back(name);
        hd->storage.emplace_back(value);
        size_t idx = hd->storage.size();
        nghttp3_nv nv;
        nv.name = reinterpret_cast<uint8_t*>(hd->storage[idx - 2].data());
        nv.namelen = hd->storage[idx - 2].size();
        nv.value = reinterpret_cast<uint8_t*>(hd->storage[idx - 1].data());
        nv.valuelen = hd->storage[idx - 1].size();
        nv.flags = NGHTTP3_NV_FLAG_NONE;
        hd->nvs.push_back(nv);
    };

    add_header(":status", status_str);
    for (const auto& [key, value] : resp.headers) {
        add_header(key, value);
    }
    if (resp.headers.find("Content-Length") == resp.headers.end()) {
        add_header("content-length", std::to_string(resp.body.size()));
    }

    // Submit response headers
    nghttp3_data_reader dr{};
    // Data reader callback for response body
    struct BodyCtx {
        std::string data;
        size_t offset = 0;
    };
    auto body_ctx = std::make_shared<BodyCtx>();
    body_ctx->data = resp.body;

    if (!resp.body.empty()) {
        dr.read_data = [](nghttp3_conn*, int64_t, nghttp3_vec* vec,
                          size_t veccnt, uint32_t* pflags,
                          void*, void* stream_user_data) -> nghttp3_ssize {
            auto* ctx = static_cast<BodyCtx*>(stream_user_data);
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

    int rv = nghttp3_conn_submit_response(h3_conn_, stream_id,
                                           hd->nvs.data(), hd->nvs.size(),
                                           resp.body.empty() ? nullptr : &dr);
    if (rv != 0) {
        LOG_ERROR("HTTP/3: failed to submit response: " + std::string(nghttp3_strerror(rv)));
    }
}

// === Packet I/O ===

std::vector<Http3Connection::OutgoingPacket>
Http3Connection::process_input(std::span<const uint8_t> data,
                                [[maybe_unused]] const std::string& peer_addr) {
    if (!quic_conn_) return {};

    bytes_received_ += data.size();

    ngtcp2_path path{};
    // In a real implementation, path would contain the actual socket addresses
    // For now, we use a placeholder

    ngtcp2_pkt_info pi{};
    auto ts = get_timestamp_ns();

    int rv = ngtcp2_conn_read_pkt(quic_conn_, &path, &pi,
                                   data.data(), data.size(), ts);
    if (rv != 0) {
        if (rv == NGTCP2_ERR_DRAINING || rv == NGTCP2_ERR_CLOSING) {
            alive_ = false;
        } else {
            LOG_WARN("HTTP/3: ngtcp2_conn_read_pkt error: " +
                     std::string(ngtcp2_strerror(rv)));
        }
    }

    if (!handshake_complete_ && ngtcp2_conn_get_handshake_completed(quic_conn_)) {
        handshake_complete_ = true;
        LOG_INFO("HTTP/3: QUIC handshake complete");
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
        ngtcp2_path_storage_zero(&ps);
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
        bytes_sent_ += static_cast<uint64_t>(n);
        packets.push_back(std::move(pkt));
    }

    return packets;
}

std::vector<Http3Connection::OutgoingPacket> Http3Connection::on_timer() {
    if (!quic_conn_) return {};

    auto ts = get_timestamp_ns();
    int rv = ngtcp2_conn_handle_expiry(quic_conn_, ts);
    if (rv != 0) {
        LOG_WARN("HTTP/3: handle_expiry error: " + std::string(ngtcp2_strerror(rv)));
        alive_ = false;
        return {};
    }

    return write_packets();
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

QuicDispatcher::QuicDispatcher(Config config, Http3Connection::RequestHandler handler)
    : config_(std::move(config)), handler_(std::move(handler)) {}

QuicDispatcher::~QuicDispatcher() {
    if (udp_fd_ >= 0) {
        close(udp_fd_);
    }
}

bool QuicDispatcher::init() {
    udp_fd_ = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    if (udp_fd_ < 0) {
        LOG_ERROR("HTTP/3: Failed to create UDP socket: " + std::string(strerror(errno)));
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
        return false;
    }

    if (bind(udp_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        LOG_ERROR("HTTP/3: Failed to bind UDP: " + std::string(strerror(errno)));
        close(udp_fd_);
        udp_fd_ = -1;
        return false;
    }

    LOG_INFO("HTTP/3: UDP listener on " + config_.bind_address + ":" +
             std::to_string(config_.port));
    return true;
}

int QuicDispatcher::process_packets() {
    if (udp_fd_ < 0) return 0;

    int count = 0;
    std::array<uint8_t, 65536> buf{};
    struct sockaddr_in peer_addr{};

    for (int i = 0; i < 64; ++i) { // Process up to 64 packets per call
        socklen_t peer_len = sizeof(peer_addr);
        auto n = recvfrom(udp_fd_, buf.data(), buf.size(), 0,
                           reinterpret_cast<struct sockaddr*>(&peer_addr), &peer_len);

        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            LOG_WARN("HTTP/3: recvfrom error: " + std::string(strerror(errno)));
            break;
        }

        ++total_packets_rx_;
        ++count;

        // Get peer address string
        char ip_buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &peer_addr.sin_addr, ip_buf, sizeof(ip_buf));
        std::string peer_str = std::string(ip_buf) + ":" + std::to_string(ntohs(peer_addr.sin_port));

        // Extract destination CID from the QUIC packet header
        // QUIC short header: first byte has form bit 0 set
        // QUIC long header: first byte has form bit 0 clear
        if (n < 1) continue;

        QuicConnectionId dcid;
        // For long headers (Initial, Handshake, etc.)
        if ((buf[0] & 0x80) != 0 && n >= 6) {
            // Long header: version (4 bytes) + dcid_len (1 byte) + dcid
            size_t dcid_len = buf[5];
            if (dcid_len > 20) dcid_len = 20;
            if (static_cast<size_t>(n) >= 6 + dcid_len) {
                dcid.len = dcid_len;
                std::memcpy(dcid.data.data(), buf.data() + 6, dcid_len);
            }
        } else if (n >= 1) {
            // Short header: CID starts at byte 1
            // Use first 16 bytes as CID (server-chosen length)
            dcid.len = 16;
            if (static_cast<size_t>(n) >= 1 + dcid.len) {
                std::memcpy(dcid.data.data(), buf.data() + 1, dcid.len);
            }
        }

        // Find or create connection
        std::lock_guard lock(connections_mutex_);
        auto* conn = find_connection(dcid);

        if (!conn) {
            // New connection (must be an Initial packet)
            if ((buf[0] & 0x80) != 0) {
                QuicConnectionId scid;
                // Extract source CID from long header
                size_t dcid_len = buf[5];
                if (dcid_len <= 20 && static_cast<size_t>(n) >= 6 + dcid_len + 1) {
                    size_t scid_len = buf[6 + dcid_len];
                    if (scid_len <= 20 && static_cast<size_t>(n) >= 7 + dcid_len + scid_len) {
                        scid.len = scid_len;
                        std::memcpy(scid.data.data(), buf.data() + 7 + dcid_len, scid_len);
                    }
                }
                conn = create_connection(scid, dcid, peer_str);
            }

            if (!conn) continue;
        }

        // Feed packet to connection
        auto replies = conn->process_input(
            std::span<const uint8_t>(buf.data(), static_cast<size_t>(n)), peer_str);

        // Send replies
        for (const auto& reply : replies) {
            sendto(udp_fd_, reply.data.data(), reply.data.size(), 0,
                   reinterpret_cast<const struct sockaddr*>(&peer_addr), peer_len);
            ++total_packets_tx_;
        }
    }

    return count;
}

int QuicDispatcher::flush_output() {
    // Iterate all connections and flush any pending output
    std::lock_guard lock(connections_mutex_);
    int count = 0;

    for (auto& [cid, conn] : connections_) {
        auto packets = conn->on_timer();
        // In a real implementation, we'd need to know the peer address for each connection
        // For now, packets are generated but not sent (needs address tracking)
        count += static_cast<int>(packets.size());
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
    auto it = connections_.find(dcid);
    if (it != connections_.end()) return it->second.get();
    return nullptr;
}

Http3Connection* QuicDispatcher::create_connection(const QuicConnectionId& scid,
                                                      const QuicConnectionId& dcid,
                                                      const std::string& peer_addr) {
    if (connections_.size() >= config_.max_connections) {
        LOG_WARN("HTTP/3: Max connections reached, rejecting " + peer_addr);
        return nullptr;
    }

    auto conn = std::make_unique<Http3Connection>(handler_, config_.transport_params);
    auto* ptr = conn.get();

    // Register by both source and destination CID for routing
    connections_[dcid] = std::move(conn);

    LOG_INFO("HTTP/3: New connection from " + peer_addr +
             " scid=" + scid.to_hex() + " dcid=" + dcid.to_hex());

    return ptr;
}

void QuicDispatcher::remove_connection(const QuicConnectionId& cid) {
    connections_.erase(cid);
}

void QuicDispatcher::cleanup_idle() {
    std::lock_guard lock(connections_mutex_);

    for (auto it = connections_.begin(); it != connections_.end(); ) {
        if (!it->second->is_alive()) {
            LOG_DEBUG("HTTP/3: Cleaning up dead connection " + it->first.to_hex());
            it = connections_.erase(it);
        } else {
            ++it;
        }
    }
}

} // namespace js
