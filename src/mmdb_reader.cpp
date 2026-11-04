#include "mmdb_reader.hpp"
#include "logger.hpp"

#include <maxminddb.h>

#include <arpa/inet.h>
#include <array>
#include <memory>
#include <string>
#include <utility>

namespace js {

struct MaxMindDbReader::Impl {
    MMDB_s database{};
    bool opened = false;

    ~Impl() {
        if (opened) MMDB_close(&database);
    }
};

MaxMindDbReader::MaxMindDbReader() = default;
MaxMindDbReader::~MaxMindDbReader() = default;
MaxMindDbReader::MaxMindDbReader(MaxMindDbReader&&) noexcept = default;
MaxMindDbReader& MaxMindDbReader::operator=(MaxMindDbReader&&) noexcept = default;

bool MaxMindDbReader::open(const std::string& path) {
    auto candidate = std::make_unique<Impl>();
    int status = MMDB_open(path.c_str(), MMDB_MODE_MMAP, &candidate->database);
    if (status != MMDB_SUCCESS) {
        LOG_ERROR("GeoIP: failed to open " + path + ": " + MMDB_strerror(status));
        return false;
    }
    candidate->opened = true;
    impl_ = std::move(candidate);
    return true;
}

bool MaxMindDbReader::is_open() const {
    return impl_ && impl_->opened;
}

std::optional<std::string> MaxMindDbReader::lookup_country(std::string_view ip) const {
    if (!is_open() || ip.empty() || ip.size() >= INET6_ADDRSTRLEN ||
        ip.find('\0') != std::string_view::npos) {
        return std::nullopt;
    }

    std::string address(ip);
    std::array<unsigned char, 16> parsed_address{};
    if (inet_pton(AF_INET, address.c_str(), parsed_address.data()) != 1 &&
        inet_pton(AF_INET6, address.c_str(), parsed_address.data()) != 1) {
        return std::nullopt;
    }

    int gai_error = 0;
    int mmdb_error = MMDB_SUCCESS;
    auto result = MMDB_lookup_string(&impl_->database, address.c_str(), &gai_error, &mmdb_error);
    if (gai_error != 0 || mmdb_error != MMDB_SUCCESS || !result.found_entry) {
        return std::nullopt;
    }

    MMDB_entry_data_s value{};
    int status = MMDB_get_value(&result.entry, &value, "country", "iso_code", nullptr);
    if (status != MMDB_SUCCESS) {
        LOG_ERROR("GeoIP: country lookup failed: " + std::string(MMDB_strerror(status)));
        return std::nullopt;
    }
    if (!value.has_data) {
        status = MMDB_get_value(&result.entry, &value, "registered_country", "iso_code", nullptr);
        if (status != MMDB_SUCCESS) {
            LOG_ERROR("GeoIP: registered-country lookup failed: " +
                      std::string(MMDB_strerror(status)));
            return std::nullopt;
        }
    }

    if (!value.has_data || value.type != MMDB_DATA_TYPE_UTF8_STRING ||
        value.data_size != 2 || value.utf8_string == nullptr) {
        return std::nullopt;
    }
    return std::string(value.utf8_string, value.data_size);
}

} // namespace js
