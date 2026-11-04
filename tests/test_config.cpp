#include "config.hpp"
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>

void run_config_tests() {
    const auto path = std::filesystem::temp_directory_path() / "justserver-test-config.conf";
    {
        std::ofstream file(path);
        file << "antibot_geoip_enabled = true\n"
             << "antibot_geoip_database = /tmp/country.mmdb\n"
        << "antibot_blocked_countries = ru, CN, ,us\n"
        << "wasm_enabled = true\n"
        << "wasm_plugin_dir = /tmp/plugins\n"
        << "wasm_max_memory_mb = 32\n"
        << "wasm_timeout_ms = 50\n"
        << "acme_enabled = true\n"
        << "acme_email = admin@example.test\n"
        << "acme_domains = example.test, www.example.test\n"
        << "acme_storage = /tmp/acme\n"
        << "acme_use_staging = true\n"
        << "http3_enabled = true\n"
        << "http3_port = 9443\n";
    }

    auto config = js::Config::load_from_file(path.string());
    std::filesystem::remove(path);
    assert(config.geoip_enabled);
    assert(config.geoip_database_path == "/tmp/country.mmdb");
    assert(config.geoip_blocked_countries.size() == 3);
    assert(config.geoip_blocked_countries[0] == "ru");
    assert(config.geoip_blocked_countries[1] == "CN");
    assert(config.geoip_blocked_countries[2] == "us");
    assert(config.wasm_enabled);
    assert(config.wasm_plugin_dir == "/tmp/plugins");
    assert(config.wasm_max_memory_bytes == 32 * 1024 * 1024);
    assert(config.wasm_execution_timeout_ms == 50);
    assert(config.acme_enabled);
    assert(config.acme_email == "admin@example.test");
    assert(config.acme_domains.size() == 2);
    assert(config.acme_storage_path == "/tmp/acme");
    assert(config.acme_use_staging);
    assert(config.http3_enabled);
    assert(config.http3_port == 9443);
    std::cout << "  [PASS] GeoIP, WASM, ACME, and HTTP/3 configuration parsing\n";
}
