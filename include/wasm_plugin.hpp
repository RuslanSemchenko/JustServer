#pragma once

#include "http_parser.hpp"
#include <string>
#include <string_view>
#include <vector>
#include <unordered_map>
#include <functional>
#include <memory>
#include <optional>
#include <chrono>
#include <mutex>

namespace js {

// WebAssembly Plugin System
// Allows users to extend JustServer with custom logic written in
// Rust, Go, AssemblyScript, or C compiled to WASM.
// Plugins run in a sandboxed environment at near-native speed.

// Plugin hook points (when plugins can intercept request processing)
enum class PluginHook {
    ON_REQUEST,           // Before any processing (can reject/modify)
    ON_RESPONSE,          // Before sending response (can modify)
    ON_ROUTE,             // Custom routing decision
    ON_AUTH,              // Authentication check
    ON_LOG,               // Custom logging/analytics
};

// Host functions exposed to WASM plugins
// These are the "syscalls" available from inside the sandbox.
struct PluginHostFunctions {
    // Read request data
    std::function<std::string()> get_request_method;
    std::function<std::string()> get_request_uri;
    std::function<std::string(const std::string& name)> get_request_header;
    std::function<std::string()> get_request_body;
    std::function<std::string()> get_client_ip;

    // Modify request
    std::function<void(const std::string& name, const std::string& value)> set_request_header;

    // Modify response
    std::function<void(int status_code)> set_response_status;
    std::function<void(const std::string& name, const std::string& value)> set_response_header;
    std::function<void(const std::string& body)> set_response_body;

    // Logging
    std::function<void(const std::string& msg)> log_info;
    std::function<void(const std::string& msg)> log_error;

    // Key-value store (shared across requests)
    std::function<std::optional<std::string>(const std::string& key)> kv_get;
    std::function<void(const std::string& key, const std::string& value)> kv_set;
};

// Plugin metadata
struct PluginInfo {
    std::string name;
    std::string version;
    std::string description;
    std::string author;
    std::vector<PluginHook> hooks;    // Which hooks this plugin registers for
};

// Plugin execution result
struct PluginResult {
    bool continue_processing = true;  // false = stop request pipeline
    bool modified_request = false;
    bool modified_response = false;
    std::string error;                // Non-empty if plugin errored
};

// Abstract WASM runtime interface
// Concrete implementations would use Wasmtime, WAMR, or Wasmer.
class WasmRuntime {
public:
    virtual ~WasmRuntime() = default;

    // Load a WASM module from file
    virtual bool load_module(const std::string& path) = 0;

    // Load a WASM module from memory
    virtual bool load_module_bytes(const uint8_t* data, size_t len) = 0;

    // Call a function in the WASM module
    virtual std::optional<int32_t> call_function(const std::string& name) = 0;

    // Set host functions that the WASM module can call
    virtual void set_host_functions(const PluginHostFunctions& funcs) = 0;

    // Get/set memory shared with the WASM module
    virtual bool write_memory(uint32_t offset, const void* data, size_t len) = 0;
    virtual bool read_memory(uint32_t offset, void* data, size_t len) = 0;

    // Get module info
    virtual PluginInfo get_info() const = 0;
};

// Plugin manager: loads, manages, and executes WASM plugins
class PluginManager {
public:
    struct Config {
        std::string plugin_dir = "/etc/justserver/plugins";
        size_t max_memory_per_plugin = 64 * 1024 * 1024; // 64 MB
        std::chrono::milliseconds execution_timeout{100}; // 100ms max per hook
        bool enabled = false; // Disabled by default
    };

    PluginManager();
    explicit PluginManager(Config config);
    ~PluginManager();

    // Non-copyable
    PluginManager(const PluginManager&) = delete;
    PluginManager& operator=(const PluginManager&) = delete;

    // Load all plugins from the plugin directory
    bool load_plugins();

    // Load a specific plugin file
    bool load_plugin(const std::string& path);

    // Unload a plugin by name
    bool unload_plugin(const std::string& name);

    // Execute all plugins registered for a specific hook
    PluginResult execute_hook(PluginHook hook, HttpRequest& req, HttpResponse& resp,
                               const std::string& client_ip);

    // List loaded plugins
    std::vector<PluginInfo> list_plugins() const;

    // Get plugin count
    size_t plugin_count() const { return plugins_.size(); }

    // Check if any plugins are registered for a hook
    bool has_plugins_for(PluginHook hook) const;

private:
    struct LoadedPlugin {
        PluginInfo info;
        std::unique_ptr<WasmRuntime> runtime;
        std::string path;
    };

    Config config_;
    std::vector<LoadedPlugin> plugins_;

    // Key-value store shared across plugins
    std::unordered_map<std::string, std::string> kv_store_;
    mutable std::mutex kv_mutex_;
};

// Stub WASM runtime (used when no WASM engine is available)
// Returns sensible defaults and logs that WASM is not available.
class StubWasmRuntime : public WasmRuntime {
public:
    bool load_module(const std::string& path) override;
    bool load_module_bytes(const uint8_t* data, size_t len) override;
    std::optional<int32_t> call_function(const std::string& name) override;
    void set_host_functions(const PluginHostFunctions& funcs) override;
    bool write_memory(uint32_t offset, const void* data, size_t len) override;
    bool read_memory(uint32_t offset, void* data, size_t len) override;
    PluginInfo get_info() const override;
};

} // namespace js
