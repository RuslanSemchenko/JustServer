#include "server.hpp"
#include "logger.hpp"
#include "metrics.hpp"

#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <csignal>
#include <cstring>
#include <poll.h>
#include <chrono>
#include <array>
#include <filesystem>
#include <sstream>
#include <grp.h>
#include <pwd.h>

#ifdef __linux__
#include <sys/prctl.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
// syscall numbers
#include <sys/syscall.h>
#endif

namespace js {

static bool set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return false;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) >= 0;
}

Server::Server(Config config, std::string config_path)
    : config_(std::move(config))
    , config_path_(std::move(config_path))
    , ddos_(DDoSGuard::Config{
        config_.max_connections_per_ip,
        config_.max_total_connections,
        config_.rate_limit_rps,
        config_.rate_limit_burst
      })
    , geoip_filter_(GeoIPFilter::Config{
        config_.geoip_database_path,
        config_.geoip_blocked_countries,
        false,
        false,
        false
      })
    , plugin_manager_(PluginManager::Config{
        config_.wasm_plugin_dir,
        config_.wasm_max_memory_bytes,
        std::chrono::milliseconds{config_.wasm_execution_timeout_ms},
        config_.wasm_enabled
      })
    , file_handler_(config_) {

    if (config_.fastcgi_enabled) {
        fcgi_ = std::make_unique<FastCGIClient>(config_.fastcgi_socket);
    }
}

Server::~Server() {
    stop();
    if (acme_challenge_thread_.joinable()) acme_challenge_thread_.join();
    if (acme_renewal_thread_.joinable()) acme_renewal_thread_.join();
    if (listen_fd_ >= 0) close(listen_fd_);
    if (epoll_fd_ >= 0) close(epoll_fd_);
    if (acme_listener_fd_ >= 0) close(acme_listener_fd_);
}

bool Server::start() {
    // Setup logging
    Logger::instance().set_level(config_.log_level);

    LOG_INFO("JustServer v1.0 starting...");
    LOG_INFO("Document root: " + config_.document_root.string());
    LOG_INFO("Bind: " + config_.bind_address + ":" + std::to_string(config_.port));
    LOG_INFO("Workers: " + std::to_string(config_.worker_threads));
    LOG_INFO("TLS: " + std::string(config_.tls_enabled ? "enabled (TLS 1.3)" : "disabled"));
    LOG_INFO("WAF: " + std::string(config_.waf_enabled ? "enabled (RE2 engine, anomaly scoring)" : "disabled"));
    LOG_INFO("FastCGI: " + std::string(config_.fastcgi_enabled ? config_.fastcgi_socket : "disabled"));
    LOG_INFO("Sendfile: enabled (zero-copy for static files)");
    LOG_INFO("HTTP/2: enabled (HPACK with Huffman, ALPN negotiation)");
    LOG_INFO("HTTP/3: " + std::string(config_.http3_enabled ? "enabled" : "disabled"));
    LOG_INFO("Security headers: " + std::string(config_.security_headers.enabled ? "enabled (CSP, HSTS, X-Content-Type-Options)" : "disabled"));
    LOG_INFO("Metrics: enabled at /metrics (Prometheus format)");
    LOG_INFO("Hot reload: SIGHUP supported");
    if (!plugin_manager_.load_plugins()) {
        LOG_ERROR("Failed to load WASM plugins");
        return false;
    }

    if (config_.geoip_enabled && !geoip_filter_.load_database()) {
        LOG_ERROR("GeoIP is enabled but its database could not be loaded");
        return false;
    }

    if (config_.acme_enabled) {
        if (!config_.tls_enabled || config_.acme_domains.empty() || config_.chroot_enabled ||
            config_.port == 80) {
            LOG_ERROR("ACME requires TLS, a non-port-80 application listener, at least one "
                      "domain, and chroot to be disabled");
            return false;
        }
        AcmeClient::Config acme_config;
        acme_config.directory_url = config_.acme_directory_url;
        acme_config.email = config_.acme_email;
        acme_config.domains = config_.acme_domains;
        acme_config.storage_path = config_.acme_storage_path;
        acme_config.use_staging = config_.acme_use_staging;
        acme_client_ = std::make_unique<AcmeClient>(std::move(acme_config));
        if (!acme_client_->initialize()) {
            LOG_ERROR("Failed to initialize ACME client");
            return false;
        }
        if (!setup_acme_challenge_listener()) {
            LOG_ERROR("Failed to bind HTTP-01 challenge listener on port 80");
            return false;
        }
        acme_listener_running_ = true;
        acme_challenge_thread_ = std::thread(&Server::acme_challenge_loop, this);
        if (!acme_client_->obtain_certificates()) {
            LOG_ERROR("Failed to obtain configured ACME certificates");
            acme_listener_running_ = false;
            shutdown(acme_listener_fd_, SHUT_RDWR);
            if (acme_challenge_thread_.joinable()) acme_challenge_thread_.join();
            return false;
        }
        auto cert = acme_client_->get_certificate(config_.acme_domains.front());
        if (!cert || !cert->valid) {
            LOG_ERROR("ACME did not provide a valid certificate for the primary domain");
            return false;
        }
        auto domain_dir = std::filesystem::path(config_.acme_storage_path) /
                          config_.acme_domains.front();
        config_.tls_cert_path = (domain_dir / "cert.pem").string();
        config_.tls_key_path = (domain_dir / "key.pem").string();
        acme_client_->set_cert_updated_callback([this, primary = config_.acme_domains.front()](
                const std::string& domain, const AcmeClient::CertInfo&) {
            if (domain != primary || !tls_ready_) return;
            if (!tls_.init(config_.tls_cert_path, config_.tls_key_path)) {
                LOG_ERROR("Failed to reload TLS certificate after ACME renewal");
            }
            if (http3_dispatcher_ && !http3_dispatcher_->reload_tls_credentials()) {
                LOG_ERROR("Failed to reload HTTP/3 TLS credentials after ACME renewal");
            }
        });
    }

    // Initialize TLS if enabled
    if (config_.tls_enabled) {
        if (!tls_.init(config_.tls_cert_path, config_.tls_key_path)) {
            if (config_.acme_enabled) {
                LOG_ERROR("Failed to initialize TLS with the ACME certificate");
                return false;
            }
            LOG_ERROR("Failed to initialize TLS. Continuing without TLS.");
            config_.tls_enabled = false;
        } else {
            tls_ready_ = true;
        }
    }

    if (config_.http3_enabled) {
        if (!config_.tls_enabled) {
            LOG_ERROR("HTTP/3 requires TLS to be enabled");
            return false;
        }

        QuicDispatcher::Config http3_config;
        http3_config.bind_address = config_.bind_address;
        http3_config.port = config_.http3_port == 0 ? config_.port : config_.http3_port;
        http3_config.tls_cert_path = config_.tls_cert_path;
        http3_config.tls_key_path = config_.tls_key_path;
        http3_config.max_connections = static_cast<size_t>(config_.max_total_connections);
        http3_config.transport_params.max_request_size_bytes =
            static_cast<size_t>(config_.max_request_size);
        http3_dispatcher_ = std::make_unique<QuicDispatcher>(
            std::move(http3_config),
            [this](const HttpRequest& req, const std::string& client_ip) {
                Worker worker(config_, &tls_, &waf_, &ddos_, &file_handler_, fcgi_.get(),
                              &geoip_filter_, &plugin_manager_);
                return worker.handle_http3_request(req, client_ip);
            });
        if (!http3_dispatcher_->init()) {
            LOG_ERROR("Failed to initialize HTTP/3 dispatcher");
            return false;
        }
    }

    // Apply security restrictions
    if (!apply_security()) {
        LOG_ERROR("Failed to apply security restrictions");
        return false;
    }

    // Setup listener
    if (!setup_listener()) {
        LOG_ERROR("Failed to setup listener");
        return false;
    }

    // Start worker threads
    running_ = true;
    for (int i = 0; i < config_.worker_threads; ++i) {
        workers_.emplace_back(&Server::worker_thread_func, this);
    }
    if (acme_client_) {
        acme_renewal_thread_ = std::thread(&Server::acme_renewal_loop, this);
    }

    LOG_INFO("Server ready. Listening on port " + std::to_string(config_.port));

    // Run event loop on main thread
    event_loop();

    // Wait for workers to finish
    for (auto& w : workers_) {
        if (w.joinable()) w.join();
    }
    acme_renewal_cv_.notify_all();
    if (acme_renewal_thread_.joinable()) acme_renewal_thread_.join();
    acme_listener_running_ = false;
    if (acme_listener_fd_ >= 0) shutdown(acme_listener_fd_, SHUT_RDWR);
    if (acme_challenge_thread_.joinable()) acme_challenge_thread_.join();

    LOG_INFO("Server stopped.");
    return true;
}

void Server::stop() {
    running_ = false;
    acme_listener_running_ = false;
    if (acme_listener_fd_ >= 0) shutdown(acme_listener_fd_, SHUT_RDWR);
    acme_renewal_cv_.notify_all();
    queue_cv_.notify_all();
}

void Server::reload_config() {
    reload_requested_ = true;
}

bool Server::setup_listener() {
    listen_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd_ < 0) {
        LOG_ERROR("Failed to create socket: " + std::string(strerror(errno)));
        return false;
    }

    // Socket options
    int opt = 1;
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(listen_fd_, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
    setsockopt(listen_fd_, IPPROTO_TCP, TCP_NODELAY, &opt, sizeof(opt));

    // Bind
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(config_.port);
    if (inet_pton(AF_INET, config_.bind_address.c_str(), &addr.sin_addr) <= 0) {
        LOG_ERROR("Invalid bind address: " + config_.bind_address);
        return false;
    }

    if (bind(listen_fd_, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) < 0) {
        LOG_ERROR("Failed to bind: " + std::string(strerror(errno)));
        return false;
    }

    if (listen(listen_fd_, config_.backlog) < 0) {
        LOG_ERROR("Failed to listen: " + std::string(strerror(errno)));
        return false;
    }

    // Set non-blocking
    set_nonblocking(listen_fd_);

    // Setup epoll
    epoll_fd_ = epoll_create1(0);
    if (epoll_fd_ < 0) {
        LOG_ERROR("Failed to create epoll: " + std::string(strerror(errno)));
        return false;
    }

    // Add listener to epoll (edge-triggered)
    struct epoll_event ev{};
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = listen_fd_;
    if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, listen_fd_, &ev) < 0) {
        LOG_ERROR("Failed to add listener to epoll: " + std::string(strerror(errno)));
        return false;
    }

    if (http3_dispatcher_) {
        ev = {};
        ev.events = EPOLLIN;
        ev.data.fd = http3_dispatcher_->socket_fd();
        if (epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, http3_dispatcher_->socket_fd(), &ev) < 0) {
            LOG_ERROR("Failed to add HTTP/3 UDP socket to epoll: " +
                      std::string(strerror(errno)));
            return false;
        }
    }

    return true;
}

bool Server::setup_acme_challenge_listener() {
    acme_listener_fd_ = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (acme_listener_fd_ < 0) {
        LOG_ERROR("ACME: failed to create challenge listener: " + std::string(strerror(errno)));
        return false;
    }
    int reuse = 1;
    setsockopt(acme_listener_fd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(80);
    if (inet_pton(AF_INET, config_.bind_address.c_str(), &address.sin_addr) != 1) {
        LOG_ERROR("ACME: HTTP-01 listener requires an IPv4 bind_address");
        return false;
    }
    if (bind(acme_listener_fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0) {
        LOG_ERROR("ACME: failed to bind TCP port 80: " + std::string(strerror(errno)));
        return false;
    }
    if (listen(acme_listener_fd_, config_.backlog) < 0) {
        LOG_ERROR("ACME: failed to listen on TCP port 80: " + std::string(strerror(errno)));
        return false;
    }
    LOG_INFO("ACME: HTTP-01 challenge listener is active on TCP port 80");
    return true;
}

void Server::acme_challenge_loop() {
    while (acme_listener_running_) {
        pollfd event{acme_listener_fd_, POLLIN, 0};
        int ready = poll(&event, 1, 500);
        if (ready <= 0) continue;
        int client = accept4(acme_listener_fd_, nullptr, nullptr, SOCK_CLOEXEC);
        if (client < 0) continue;
        timeval timeout{2, 0};
        setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        std::string request;
        std::array<char, 1024> buffer{};
        while (request.size() < 8192 && request.find("\r\n\r\n") == std::string::npos) {
            ssize_t count = recv(client, buffer.data(), buffer.size(), 0);
            if (count <= 0) break;
            request.append(buffer.data(), static_cast<size_t>(count));
        }

        int status = 404;
        std::string body = "Not Found\n";
        auto line_end = request.find("\r\n");
        if (line_end != std::string::npos) {
            std::istringstream first_line(request.substr(0, line_end));
            std::string method, target;
            first_line >> method >> target;
            constexpr std::string_view challenge_prefix = "/.well-known/acme-challenge/";
            if (method == "GET" && target.starts_with(challenge_prefix) &&
                target.find_first_of("?#", challenge_prefix.size()) == std::string::npos) {
                auto token = target.substr(challenge_prefix.size());
                if (!token.empty() && token.find('/') == std::string::npos) {
                    auto key_authorization = acme_client_->handle_challenge(token);
                    if (key_authorization) {
                        status = 200;
                        body = *key_authorization;
                    }
                }
            }
        }
        auto reason = status == 200 ? "OK" : "Not Found";
        auto response = "HTTP/1.1 " + std::to_string(status) + " " + reason +
            "\r\nContent-Type: text/plain\r\nContent-Length: " +
            std::to_string(body.size()) + "\r\nConnection: close\r\n\r\n" + body;
        size_t sent = 0;
        while (sent < response.size()) {
            ssize_t count = send(client, response.data() + sent, response.size() - sent,
                                 MSG_NOSIGNAL);
            if (count <= 0) break;
            sent += static_cast<size_t>(count);
        }
        close(client);
    }
}

void Server::acme_renewal_loop() {
    std::unique_lock lock(acme_renewal_mutex_);
    while (running_) {
        if (acme_renewal_cv_.wait_for(lock, std::chrono::hours(12),
                                      [this] { return !running_.load(); })) {
            break;
        }
        lock.unlock();
        if (running_ && acme_client_ && !acme_client_->check_and_renew()) {
            LOG_ERROR("ACME: automatic certificate renewal check failed");
        }
        lock.lock();
    }
}

bool Server::apply_security() {
    // --- RLIMIT: cap memory and file descriptors ---
    {
        struct rlimit rl{};

        // RLIMIT_AS: virtual address space limit
        if (config_.max_memory_bytes > 0) {
            rl.rlim_cur = config_.max_memory_bytes;
            rl.rlim_max = config_.max_memory_bytes;
            if (setrlimit(RLIMIT_AS, &rl) == 0) {
                LOG_INFO("RLIMIT_AS set to " + std::to_string(config_.max_memory_bytes / (1024*1024)) + " MB");
            } else {
                LOG_WARN("Failed to set RLIMIT_AS: " + std::string(strerror(errno)));
            }
        }

        // RLIMIT_NOFILE: max open file descriptors
        if (config_.max_open_files > 0) {
            rl.rlim_cur = static_cast<rlim_t>(config_.max_open_files);
            rl.rlim_max = static_cast<rlim_t>(config_.max_open_files);
            if (setrlimit(RLIMIT_NOFILE, &rl) == 0) {
                LOG_INFO("RLIMIT_NOFILE set to " + std::to_string(config_.max_open_files));
            } else {
                LOG_WARN("Failed to set RLIMIT_NOFILE: " + std::string(strerror(errno)));
            }
        }
    }

    if (acme_client_ && (config_.drop_uid >= 0 || config_.drop_gid >= 0)) {
        uid_t owner = config_.drop_uid >= 0 ? static_cast<uid_t>(config_.drop_uid) : geteuid();
        gid_t group = config_.drop_gid >= 0 ? static_cast<gid_t>(config_.drop_gid) : getegid();
        std::error_code ec;
        auto storage = std::filesystem::path(config_.acme_storage_path);
        auto change_owner = [&](const std::filesystem::path& path) {
            auto status = std::filesystem::symlink_status(path, ec);
            if (ec || std::filesystem::is_symlink(status) ||
                chown(path.c_str(), owner, group) != 0) {
                LOG_ERROR("ACME: cannot prepare storage ownership for privilege drop: " +
                          path.string() + (ec ? ": " + ec.message()
                                              : ": " + std::string(strerror(errno))));
                return false;
            }
            return true;
        };
        if (!change_owner(storage)) return false;
        std::filesystem::recursive_directory_iterator it(storage, ec), end;
        if (ec) {
            LOG_ERROR("ACME: cannot inspect storage before privilege drop: " + ec.message());
            return false;
        }
        for (; it != end; it.increment(ec)) {
            if (ec) {
                LOG_ERROR("ACME: cannot inspect storage before privilege drop: " + ec.message());
                return false;
            }
            if (!change_owner(it->path())) return false;
        }
    }

    // --- Chroot if enabled (must be root, must happen before privilege drop) ---
    // Fail closed: if the operator asked for a chroot we must not keep running
    // unjailed. chdir("/") is mandatory right after chroot(), otherwise the
    // working directory stays outside the jail (classic chroot escape).
    if (config_.chroot_enabled) {
        if (chroot(config_.document_root.c_str()) != 0) {
            LOG_ERROR("Failed to chroot (requires root): " + std::string(strerror(errno)));
            return false;
        }
        if (chdir("/") != 0) {
            LOG_ERROR("chdir(\"/\") after chroot failed: " + std::string(strerror(errno)));
            return false;
        }
        LOG_INFO("Chroot to: " + config_.document_root.string());
        config_.document_root = "/";
    }

    // --- Drop privileges: setgroups, setgid, then setuid (order matters!) ---
    // This must happen AFTER bind(), TLS cert loading, and chroot().
    // Fail closed: a failed drop must never leave the server running as root.
    if (config_.drop_gid >= 0) {
        gid_t gid = static_cast<gid_t>(config_.drop_gid);
        if (setgroups(0, nullptr) != 0) {
            if (geteuid() == 0) {
                LOG_ERROR("Failed to clear supplementary groups: " + std::string(strerror(errno)));
                return false;
            }
            // Not root: clearing groups is not permitted (EPERM), keep going.
            LOG_WARN("Cannot clear supplementary groups (not root): " + std::string(strerror(errno)));
        }
        if (setgid(gid) != 0) {
            LOG_ERROR("Failed to setgid(" + std::to_string(gid) + "): " + std::string(strerror(errno)));
            return false;
        }
        LOG_INFO("Dropped group privileges to GID " + std::to_string(gid));
    }
    if (config_.drop_uid >= 0) {
        uid_t uid = static_cast<uid_t>(config_.drop_uid);
        if (setuid(uid) != 0) {
            LOG_ERROR("Failed to setuid(" + std::to_string(uid) + "): " + std::string(strerror(errno)));
            return false;
        }
        LOG_INFO("Dropped user privileges to UID " + std::to_string(uid));
        // Verify we cannot re-escalate
        if (setuid(0) == 0) {
            LOG_ERROR("CRITICAL: was able to regain root after setuid -- aborting");
            return false;
        }
    }

    // Ignore SIGPIPE (broken pipe from client disconnect)
    signal(SIGPIPE, SIG_IGN);

#ifdef __linux__
    // --- seccomp: restrict syscalls to a safe allowlist ---
    // Only enable if we successfully dropped privileges (running as non-root)
    if (config_.drop_uid >= 0 && getuid() != 0) {
        // Use seccomp strict mode with BPF filter
        // Allow essential syscalls for a network server
        struct sock_filter filter[] = {
            // Load syscall number
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),

            // Allow networking
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_read, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_write, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_close, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_sendto, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_recvfrom, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_sendmsg, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_recvmsg, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_accept4, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_socket, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_connect, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_setsockopt, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getsockopt, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_shutdown, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

            // Allow epoll
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_epoll_wait, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_epoll_ctl, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_epoll_pwait, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_poll, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

            // Allow file operations (for static file serving & logging)
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_openat, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_fstat, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_newfstatat, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_lseek, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_sendfile, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getdents64, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_fchmod, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_fchmodat, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_fsync, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_rename, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_unlink, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

            // Allow memory management
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_mmap, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_munmap, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_mprotect, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_brk, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_mremap, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

            // Allow threading / futex
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_futex, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clone3, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_set_robust_list, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_rseq, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

            // Allow time / clock
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clock_gettime, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_gettimeofday, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_nanosleep, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_clock_nanosleep, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

            // Allow signal handling
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_rt_sigaction, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_rt_sigprocmask, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_rt_sigreturn, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

            // Allow io_uring
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_io_uring_setup, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_io_uring_enter, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_io_uring_register, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

            // Allow misc needed syscalls
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_exit_group, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_fcntl, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_ioctl, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getrandom, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getpid, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_gettid, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_tgkill, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_writev, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_readv, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_pread64, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_pwrite64, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_madvise, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getuid, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getgid, 0, 1),
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),

            // Default: log and deny (SECCOMP_RET_LOG requires kernel 4.14+,
            // falls back to ERRNO on older kernels)
            BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        };

        struct sock_fprog prog = {
            .len = static_cast<unsigned short>(sizeof(filter) / sizeof(filter[0])),
            .filter = filter,
        };

        // Allow ourselves to install the filter
        if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0) {
            if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog) == 0) {
                LOG_INFO("seccomp BPF filter installed: syscall allowlist active");
            } else {
                LOG_WARN("Failed to install seccomp filter: " + std::string(strerror(errno)));
            }
        } else {
            LOG_WARN("Failed to set PR_SET_NO_NEW_PRIVS: " + std::string(strerror(errno)));
        }
    }
#endif

    return true;
}

void Server::event_loop() {
    constexpr int MAX_EVENTS = 256;
    struct epoll_event events[MAX_EVENTS];

    while (running_) {
        // Check for hot reload request (SIGHUP)
        if (reload_requested_.exchange(false)) {
            LOG_INFO("SIGHUP received: reloading configuration...");

            if (!config_path_.empty()) {
                auto new_config = Config::load_from_file(config_path_);

                // Update DDoS guard limits
                ddos_.set_max_per_ip(new_config.max_connections_per_ip);

                // Update WAF state
                config_.waf_enabled = new_config.waf_enabled;
                config_.max_connections_per_ip = new_config.max_connections_per_ip;
                config_.header_read_timeout_ms = new_config.header_read_timeout_ms;
                config_.request_body_timeout_ms = new_config.request_body_timeout_ms;
                config_.max_request_size = new_config.max_request_size;
                config_.log_level = new_config.log_level;

                Logger::instance().set_level(config_.log_level);
                LOG_INFO("Configuration reloaded successfully");
            } else {
                LOG_WARN("No config file path set, cannot reload");
            }
        }

        int nfds = epoll_wait(epoll_fd_, events, MAX_EVENTS,
                              http3_dispatcher_ ? 50 : 1000);

        if (nfds < 0) {
            if (errno == EINTR) continue;
            LOG_ERROR("epoll_wait error: " + std::string(strerror(errno)));
            break;
        }

        for (int i = 0; i < nfds; ++i) {
            if (events[i].data.fd == listen_fd_) {
                // Accept all pending connections (edge-triggered)
                while (true) {
                    struct sockaddr_in client_addr{};
                    socklen_t client_len = sizeof(client_addr);

                    int client_fd = accept4(listen_fd_,
                        reinterpret_cast<struct sockaddr*>(&client_addr),
                        &client_len, SOCK_CLOEXEC);

                    if (client_fd < 0) {
                        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                        LOG_WARN("accept failed: " + std::string(strerror(errno)));
                        break;
                    }

                    // Get client IP
                    char ip_buf[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &client_addr.sin_addr, ip_buf, sizeof(ip_buf));
                    std::string client_ip(ip_buf);

                    // DDoS check
                    if (!ddos_.allow_connection(client_ip)) {
                        Metrics::instance().record_blocked_ip();
                        close(client_fd);
                        continue;
                    }

                    // Enqueue for worker
                    {
                        std::lock_guard lock(queue_mutex_);
                        pending_.push({client_fd, std::move(client_ip)});
                    }
                    queue_cv_.notify_one();
                }
            } else if (http3_dispatcher_ &&
                       events[i].data.fd == http3_dispatcher_->socket_fd()) {
                http3_dispatcher_->process_packets();
            }
        }
        if (http3_dispatcher_) {
            http3_dispatcher_->flush_output();
            http3_dispatcher_->tick();
        }
    }
}

void Server::worker_thread_func() {
    Worker worker(config_, &tls_, &waf_, &ddos_, &file_handler_, fcgi_.get(),
                  &geoip_filter_, &plugin_manager_);

    while (running_) {
        PendingConnection conn;

        {
            std::unique_lock lock(queue_mutex_);
            queue_cv_.wait(lock, [this] {
                return !pending_.empty() || !running_;
            });

            if (!running_ && pending_.empty()) return;

            conn = std::move(pending_.front());
            pending_.pop();
        }

        worker.handle_connection(conn.fd, conn.client_ip);
    }
}

} // namespace js
