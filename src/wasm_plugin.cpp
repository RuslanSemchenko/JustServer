#include "wasm_plugin.hpp"
#include "logger.hpp"

#include <filesystem>
#include <algorithm>

namespace js {

// === PluginManager ===

PluginManager::PluginManager() : config_{} {}
PluginManager::PluginManager(Config config) : config_(std::move(config)) {}

PluginManager::~PluginManager() = default;

bool PluginManager::load_plugins() {
    if (!config_.enabled) {
        LOG_INFO("WASM plugins: disabled");
        return true;
    }

    if (!std::filesystem::exists(config_.plugin_dir)) {
        LOG_WARN("WASM plugin directory does not exist: " + config_.plugin_dir);
        return true;
    }

    int loaded = 0;
    for (const auto& entry : std::filesystem::directory_iterator(config_.plugin_dir)) {
        if (entry.path().extension() == ".wasm") {
            if (load_plugin(entry.path().string())) {
                ++loaded;
            }
        }
    }

    LOG_INFO("WASM plugins: loaded " + std::to_string(loaded) + " plugins from " + config_.plugin_dir);
    return true;
}

bool PluginManager::load_plugin(const std::string& path) {
    LOG_INFO("Loading WASM plugin: " + path);

    auto runtime = std::make_unique<StubWasmRuntime>();
    if (!runtime->load_module(path)) {
        LOG_ERROR("Failed to load WASM module: " + path);
        return false;
    }

    auto info = runtime->get_info();
    info.name = std::filesystem::path(path).stem().string();

    LoadedPlugin plugin;
    plugin.info = std::move(info);
    plugin.runtime = std::move(runtime);
    plugin.path = path;

    LOG_INFO("WASM plugin loaded: " + plugin.info.name +
             " v" + plugin.info.version);

    plugins_.push_back(std::move(plugin));
    return true;
}

bool PluginManager::unload_plugin(const std::string& name) {
    auto it = std::remove_if(plugins_.begin(), plugins_.end(),
        [&name](const LoadedPlugin& p) { return p.info.name == name; });

    if (it == plugins_.end()) return false;

    plugins_.erase(it, plugins_.end());
    LOG_INFO("WASM plugin unloaded: " + name);
    return true;
}

PluginResult PluginManager::execute_hook(PluginHook hook, HttpRequest& req, HttpResponse& resp,
                                           const std::string& client_ip) {
    PluginResult result;

    for (auto& plugin : plugins_) {
        // Check if this plugin is registered for the hook
        bool registered = false;
        for (auto h : plugin.info.hooks) {
            if (h == hook) { registered = true; break; }
        }
        if (!registered) continue;

        // Set up host functions for this request
        PluginHostFunctions funcs;
        funcs.get_request_method = [&]() { return req.method_str; };
        funcs.get_request_uri = [&]() { return req.uri; };
        funcs.get_request_header = [&](const std::string& name) {
            return std::string(req.get_header(name));
        };
        funcs.get_request_body = [&]() { return req.body; };
        funcs.get_client_ip = [&]() { return client_ip; };

        funcs.set_request_header = [&](const std::string& name, const std::string& value) {
            req.headers[name] = value;
            result.modified_request = true;
        };
        funcs.set_response_status = [&](int code) {
            resp.status_code = code;
            result.modified_response = true;
        };
        funcs.set_response_header = [&](const std::string& name, const std::string& value) {
            resp.headers[name] = value;
            result.modified_response = true;
        };
        funcs.set_response_body = [&](const std::string& body) {
            resp.body = body;
            result.modified_response = true;
        };

        funcs.log_info = [&](const std::string& msg) {
            LOG_INFO("[plugin:" + plugin.info.name + "] " + msg);
        };
        funcs.log_error = [&](const std::string& msg) {
            LOG_ERROR("[plugin:" + plugin.info.name + "] " + msg);
        };

        funcs.kv_get = [this](const std::string& key) -> std::optional<std::string> {
            std::lock_guard lock(kv_mutex_);
            auto it = kv_store_.find(key);
            if (it != kv_store_.end()) return it->second;
            return std::nullopt;
        };
        funcs.kv_set = [this](const std::string& key, const std::string& value) {
            std::lock_guard lock(kv_mutex_);
            kv_store_[key] = value;
        };

        plugin.runtime->set_host_functions(funcs);

        // Call the appropriate hook function
        std::string hook_name;
        switch (hook) {
            case PluginHook::ON_REQUEST:  hook_name = "on_request"; break;
            case PluginHook::ON_RESPONSE: hook_name = "on_response"; break;
            case PluginHook::ON_ROUTE:    hook_name = "on_route"; break;
            case PluginHook::ON_AUTH:     hook_name = "on_auth"; break;
            case PluginHook::ON_LOG:      hook_name = "on_log"; break;
        }

        auto ret = plugin.runtime->call_function(hook_name);
        if (ret && *ret != 0) {
            // Plugin returned non-zero = stop processing
            result.continue_processing = false;
            break;
        }
    }

    return result;
}

std::vector<PluginInfo> PluginManager::list_plugins() const {
    std::vector<PluginInfo> result;
    result.reserve(plugins_.size());
    for (const auto& p : plugins_) {
        result.push_back(p.info);
    }
    return result;
}

bool PluginManager::has_plugins_for(PluginHook hook) const {
    for (const auto& plugin : plugins_) {
        for (auto h : plugin.info.hooks) {
            if (h == hook) return true;
        }
    }
    return false;
}

// === StubWasmRuntime ===

bool StubWasmRuntime::load_module(const std::string& path) {
    LOG_WARN("WASM: Stub runtime loading " + path +
             " (install Wasmtime for real WASM execution)");
    return std::filesystem::exists(path);
}

bool StubWasmRuntime::load_module_bytes([[maybe_unused]] const uint8_t* data,
                                          [[maybe_unused]] size_t len) {
    LOG_WARN("WASM: Stub runtime (no real WASM execution available)");
    return true;
}

std::optional<int32_t> StubWasmRuntime::call_function(const std::string& name) {
    LOG_DEBUG("WASM stub: call_function(" + name + ") - no-op");
    return 0; // Success, continue processing
}

void StubWasmRuntime::set_host_functions([[maybe_unused]] const PluginHostFunctions& funcs) {
    // Stub: no-op
}

bool StubWasmRuntime::write_memory([[maybe_unused]] uint32_t offset,
                                     [[maybe_unused]] const void* data,
                                     [[maybe_unused]] size_t len) {
    return false;
}

bool StubWasmRuntime::read_memory([[maybe_unused]] uint32_t offset,
                                    [[maybe_unused]] void* data,
                                    [[maybe_unused]] size_t len) {
    return false;
}

PluginInfo StubWasmRuntime::get_info() const {
    return {"stub", "0.0.0", "Stub WASM runtime", "JustServer", {}};
}

} // namespace js
