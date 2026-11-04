#pragma once

#include "config.hpp"
#include "tls_context.hpp"
#include "waf.hpp"
#include "ddos_guard.hpp"
#include "file_handler.hpp"
#include "fastcgi_client.hpp"
#include "worker.hpp"
#include "anti_bot.hpp"
#include "wasm_plugin.hpp"
#include "acme_client.hpp"
#include "http3.hpp"

#include <atomic>
#include <thread>
#include <vector>
#include <queue>
#include <mutex>
#include <condition_variable>

namespace js {

class Server {
public:
    explicit Server(Config config, std::string config_path = "");
    ~Server();

    // Non-copyable
    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;

    // Start serving (blocks)
    bool start();

    // Signal stop
    void stop();

    // Hot reload configuration (SIGHUP handler)
    void reload_config();

private:
    // Setup listener socket
    bool setup_listener();
    bool setup_acme_challenge_listener();
    void acme_challenge_loop();
    void acme_renewal_loop();

    // Apply security restrictions (chroot, drop privileges)
    bool apply_security();

    // Main event loop (epoll reactor)
    void event_loop();

    // Worker thread pool
    void worker_thread_func();

    struct PendingConnection {
        int fd;
        std::string client_ip;
    };

    Config config_;
    std::string config_path_;

    // Components
    TLSContext tls_;
    WAF waf_;
    DDoSGuard ddos_;
    GeoIPFilter geoip_filter_;
    PluginManager plugin_manager_;
    std::unique_ptr<AcmeClient> acme_client_;
    std::unique_ptr<QuicDispatcher> http3_dispatcher_;
    FileHandler file_handler_;
    std::unique_ptr<FastCGIClient> fcgi_;

    // Server state
    int listen_fd_ = -1;
    int epoll_fd_ = -1;
    int acme_listener_fd_ = -1;
    std::atomic<bool> running_{false};
    std::atomic<bool> acme_listener_running_{false};
    std::atomic<bool> tls_ready_{false};
    std::atomic<bool> reload_requested_{false};
    std::thread acme_challenge_thread_;
    std::thread acme_renewal_thread_;
    std::mutex acme_renewal_mutex_;
    std::condition_variable acme_renewal_cv_;

    // Thread pool
    std::vector<std::thread> workers_;
    std::queue<PendingConnection> pending_;
    std::mutex queue_mutex_;
    std::condition_variable queue_cv_;
};

} // namespace js
