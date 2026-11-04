#pragma once

#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace js {

class MaxMindDbReader {
public:
    MaxMindDbReader();
    ~MaxMindDbReader();

    MaxMindDbReader(const MaxMindDbReader&) = delete;
    MaxMindDbReader& operator=(const MaxMindDbReader&) = delete;
    MaxMindDbReader(MaxMindDbReader&&) noexcept;
    MaxMindDbReader& operator=(MaxMindDbReader&&) noexcept;

    bool open(const std::string& path);
    bool is_open() const;
    std::optional<std::string> lookup_country(std::string_view ip) const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace js
