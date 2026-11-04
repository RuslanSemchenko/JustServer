#pragma once

#include "wasm_plugin.hpp"

#include <chrono>
#include <memory>

namespace js {

class WasmInterpreter final : public WasmRuntime {
public:
    explicit WasmInterpreter(
        size_t max_memory_bytes = 64 * 1024 * 1024,
        std::chrono::milliseconds execution_timeout = std::chrono::milliseconds{100});
    ~WasmInterpreter() override;

    WasmInterpreter(const WasmInterpreter&) = delete;
    WasmInterpreter& operator=(const WasmInterpreter&) = delete;

    bool load_module(const std::string& path) override;
    bool load_module_bytes(const uint8_t* data, size_t len) override;
    std::optional<int32_t> call_function(const std::string& name) override;
    void set_host_functions(const PluginHostFunctions& funcs) override;
    bool write_memory(uint32_t offset, const void* data, size_t len) override;
    bool read_memory(uint32_t offset, void* data, size_t len) override;
    PluginInfo get_info() const override;
    std::string last_error() const override;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace js
