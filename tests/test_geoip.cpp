#include "anti_bot.hpp"
#include "mmdb_reader.hpp"
#include <cassert>
#include <filesystem>
#include <fstream>
#include <iostream>

void run_geoip_tests() {
    js::MaxMindDbReader reader;
    assert(!reader.is_open());
    assert(!reader.lookup_country("127.0.0.1"));
    assert(!reader.open("/path/that/does/not/exist.mmdb"));
    assert(!reader.is_open());

    js::GeoIPFilter::Config config;
    config.blocked_countries = {"US"};
    js::GeoIPFilter filter(config);
    assert(!filter.is_blocked("127.0.0.1"));
    assert(!filter.load_database());

    const auto invalid_db = std::filesystem::temp_directory_path() /
                            "justserver-invalid-geoip.mmdb";
    {
        std::ofstream file(invalid_db);
        file << "not a MaxMind database";
    }
    config.database_path = invalid_db.string();
    js::GeoIPFilter invalid_filter(config);
    assert(!invalid_filter.load_database());
    std::filesystem::remove(invalid_db);
    std::cout << "  [PASS] GeoIP database validation\n";
}
