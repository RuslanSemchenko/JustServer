#include "server.hpp"
#include "logger.hpp"

#include <csignal>
#include <cstring>
#include <iostream>
#include <thread>

static js::Server* g_server = nullptr;

static void signal_handler(int sig) {
    if (!g_server) return;

    if (sig == SIGHUP) {
        LOG_INFO("SIGHUP received: requesting hot config reload...");
        g_server->reload_config();
    } else {
        LOG_INFO("Received signal " + std::to_string(sig) + ", shutting down...");
        g_server->stop();
    }
}

static void print_usage(const char* prog) {
    std::cerr << "Usage: " << prog << " [options]\n"
              << "Options:\n"
              << "  -c <path>    Config file path (default: /etc/justserver/justserver.conf)\n"
              << "  -p <port>    Listen port (default: 8443)\n"
              << "  -d <path>    Document root (default: /var/www/html)\n"
              << "  -w <count>   Worker threads (default: CPU count)\n"
              << "  --no-tls     Disable TLS\n"
              << "  --no-waf     Disable WAF\n"
              << "  --no-fcgi    Disable FastCGI\n"
              << "  -h, --help   Show this help\n"
              << "\nSignals:\n"
              << "  SIGHUP       Hot reload configuration\n"
              << "  SIGINT/TERM  Graceful shutdown\n"
              << "\nEndpoints:\n"
              << "  /metrics     Prometheus metrics\n";
}

int main(int argc, char* argv[]) {
    js::Config config = js::Config::defaults();
    std::string config_file;

    // Default worker count to hardware concurrency
    auto hw_threads = std::thread::hardware_concurrency();
    if (hw_threads > 0) {
        config.worker_threads = static_cast<int>(hw_threads);
    }

    // Parse command line arguments
    for (int i = 1; i < argc; ++i) {
        std::string_view arg(argv[i]);

        if (arg == "-c" && i + 1 < argc) {
            config_file = argv[++i];
        } else if (arg == "-p" && i + 1 < argc) {
            config.port = static_cast<uint16_t>(std::stoi(argv[++i]));
        } else if (arg == "-d" && i + 1 < argc) {
            config.document_root = argv[++i];
        } else if (arg == "-w" && i + 1 < argc) {
            config.worker_threads = std::stoi(argv[++i]);
        } else if (arg == "--no-tls") {
            config.tls_enabled = false;
        } else if (arg == "--no-waf") {
            config.waf_enabled = false;
        } else if (arg == "--no-fcgi") {
            config.fastcgi_enabled = false;
        } else if (arg == "-h" || arg == "--help") {
            print_usage(argv[0]);
            return 0;
        } else {
            std::cerr << "Unknown option: " << arg << "\n";
            print_usage(argv[0]);
            return 1;
        }
    }

    // Load config file if specified
    if (!config_file.empty()) {
        config = js::Config::load_from_file(config_file);
    }

    // Setup signal handlers
    struct sigaction sa{};
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, nullptr);
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGHUP, &sa, nullptr);  // Hot config reload

    // Create and start server
    js::Server server(std::move(config), config_file);
    g_server = &server;

    if (!server.start()) {
        LOG_ERROR("Server failed to start");
        return 1;
    }

    g_server = nullptr;
    return 0;
}
