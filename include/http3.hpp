#pragma once

#include "http_parser.hpp"
#include "stream.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <functional>
#include <optional>
#include <memory>
#include <chrono>
#include <mutex>
#include <array>
#include <span>

// Forward declarations for ngtcp2/nghttp3 types
struct ngtcp2_conn;
struct nghttp3_conn;
struct nghttp3_rcbuf;

namespace js {

// Connection ID for QUIC routing
struct QuicConnectionId {
    std::array<uint8_t, 20> data{};
    size_t len = 0;

    bool operator==(const QuicConnectionId& other) const;
    std::string to_hex() const;
    static QuicConnectionId generate(size_t length = 16);
};

// Hash for QuicConnectionId (used in unordered_map)
struct QuicConnectionIdHash {
    size_t operator()(const QuicConnectionId& cid) const;
};

// QUIC transport parameters
struct QuicTransportParams {
    uint64_t max_idle_timeout_ms = 30000;
    uint64_t initial_max_data = 1048576;            // 1 MB
    uint64_t initial_max_stream_data_bidi_local = 262144;  // 256 KB
    uint64_t initial_max_stream_data_bidi_remote = 262144;
    uint64_t initial_max_stream_data_uni = 262144;
    uint64_t initial_max_streams_bidi = 100;
    uint64_t initial_max_streams_uni = 3;
    uint64_t max_udp_payload_size = 1350;
    bool disable_active_migration = true;
};

// A single QUIC connection handling HTTP/3
class Http3Connection {
public:
    using RequestHandler = std::function<HttpResponse(const HttpRequest&)>;

    Http3Connection(RequestHandler handler, const QuicTransportParams& params);
    ~Http3Connection();

    // Non-copyable
    Http3Connection(const Http3Connection&) = delete;
    Http3Connection& operator=(const Http3Connection&) = delete;

    // Process incoming UDP data, returns UDP packets to send back
    struct OutgoingPacket {
        std::vector<uint8_t> data;
        // Destination address info would go here for real routing
    };
    std::vector<OutgoingPacket> process_input(std::span<const uint8_t> data,
                                                const std::string& peer_addr);

    // Periodic timer: call to handle retransmission, idle timeout, etc.
    std::vector<OutgoingPacket> on_timer();

    // Get the next timeout (when on_timer should be called)
    std::chrono::milliseconds next_timeout() const;

    // Connection state
    bool is_alive() const;
    bool is_handshake_complete() const;

    // Get connection IDs
    QuicConnectionId source_cid() const { return scid_; }
    QuicConnectionId dest_cid() const { return dcid_; }

    // Stats
    uint64_t bytes_sent() const { return bytes_sent_; }
    uint64_t bytes_received() const { return bytes_received_; }
    uint64_t streams_opened() const { return streams_opened_; }

private:
    // ngtcp2 callbacks
    static int on_recv_stream_data(ngtcp2_conn* conn, uint32_t flags,
                                    int64_t stream_id, uint64_t offset,
                                    const uint8_t* data, size_t datalen,
                                    void* user_data, void* stream_user_data);
    static int on_stream_open(ngtcp2_conn* conn, int64_t stream_id, void* user_data);
    static int on_stream_close(ngtcp2_conn* conn, uint32_t flags,
                                int64_t stream_id, uint64_t app_error_code,
                                void* user_data, void* stream_user_data);
    static int on_acked_stream_data_offset(ngtcp2_conn* conn, int64_t stream_id,
                                            uint64_t offset, uint64_t datalen,
                                            void* user_data, void* stream_user_data);

    // nghttp3 callbacks
    static int on_h3_recv_header(nghttp3_conn* conn, int64_t stream_id,
                                  int32_t token, nghttp3_rcbuf* name,
                                  nghttp3_rcbuf* value, uint8_t flags,
                                  void* user_data, void* stream_user_data);
    static int on_h3_end_headers(nghttp3_conn* conn, int64_t stream_id,
                                  int token, void* user_data, void* stream_user_data);
    static int on_h3_recv_data(nghttp3_conn* conn, int64_t stream_id,
                                const uint8_t* data, size_t datalen,
                                void* user_data, void* stream_user_data);
    static int on_h3_end_stream(nghttp3_conn* conn, int64_t stream_id,
                                 void* user_data, void* stream_user_data);

    // Internal helpers
    std::vector<OutgoingPacket> write_packets();
    void send_response(int64_t stream_id, const HttpResponse& resp);

    // Per-stream request accumulation
    struct StreamContext {
        HttpRequest request;
        bool headers_complete = false;
        bool data_complete = false;
    };

    RequestHandler handler_;
    QuicTransportParams params_;

    ngtcp2_conn* quic_conn_ = nullptr;
    nghttp3_conn* h3_conn_ = nullptr;

    QuicConnectionId scid_;
    QuicConnectionId dcid_;

    std::unordered_map<int64_t, StreamContext> streams_;
    bool alive_ = true;
    bool handshake_complete_ = false;

    // Stats
    uint64_t bytes_sent_ = 0;
    uint64_t bytes_received_ = 0;
    uint64_t streams_opened_ = 0;
};

// UDP dispatcher: routes incoming QUIC packets to the correct connection
// by Connection ID. This is the main entry point for HTTP/3.
class QuicDispatcher {
public:
    struct Config {
        uint16_t port = 443;
        std::string bind_address = "0.0.0.0";
        QuicTransportParams transport_params;
        std::string tls_cert_path;
        std::string tls_key_path;
        size_t max_connections = 10000;
    };

    QuicDispatcher(Config config, Http3Connection::RequestHandler handler);
    ~QuicDispatcher();

    // Non-copyable
    QuicDispatcher(const QuicDispatcher&) = delete;
    QuicDispatcher& operator=(const QuicDispatcher&) = delete;

    // Initialize the UDP socket
    bool init();

    // Process one batch of incoming UDP packets
    // Returns number of packets processed
    int process_packets();

    // Send any pending outgoing packets
    int flush_output();

    // Periodic maintenance (retransmissions, idle timeout cleanup)
    void tick();

    // Stats
    size_t active_connections() const;
    uint64_t total_packets_received() const { return total_packets_rx_; }
    uint64_t total_packets_sent() const { return total_packets_tx_; }

private:
    // Route a packet to the appropriate connection by CID
    Http3Connection* find_connection(const QuicConnectionId& dcid);

    // Create a new connection for an Initial packet
    Http3Connection* create_connection(const QuicConnectionId& scid,
                                         const QuicConnectionId& dcid,
                                         const std::string& peer_addr);

    // Remove a dead connection
    void remove_connection(const QuicConnectionId& cid);

    // Clean up idle connections
    void cleanup_idle();

    Config config_;
    Http3Connection::RequestHandler handler_;

    int udp_fd_ = -1;

    // Connection map: CID -> connection
    std::unordered_map<QuicConnectionId, std::unique_ptr<Http3Connection>,
                       QuicConnectionIdHash> connections_;
    mutable std::mutex connections_mutex_;

    // Stats
    uint64_t total_packets_rx_ = 0;
    uint64_t total_packets_tx_ = 0;
};

} // namespace js
