#include "wasm_interpreter.hpp"

#include <array>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace {

void append_u32(std::vector<uint8_t>& out, uint32_t value) {
    do {
        uint8_t byte = static_cast<uint8_t>(value & 0x7f);
        value >>= 7;
        if (value != 0) byte |= 0x80;
        out.push_back(byte);
    } while (value != 0);
}

void append_string(std::vector<uint8_t>& out, std::string_view value) {
    append_u32(out, static_cast<uint32_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
}

void append_section(std::vector<uint8_t>& module, uint8_t id,
                    const std::vector<uint8_t>& payload) {
    module.push_back(id);
    append_u32(module, static_cast<uint32_t>(payload.size()));
    module.insert(module.end(), payload.begin(), payload.end());
}

std::vector<uint8_t> module_with_function(std::vector<uint8_t> code,
                                          bool memory = false,
                                          std::vector<uint8_t> data = {}) {
    std::vector<uint8_t> module{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00};
    append_section(module, 1, {1, 0x60, 0, 1, 0x7f});
    append_section(module, 3, {1, 0});
    if (memory) append_section(module, 5, {1, 0, 1});
    std::vector<uint8_t> exports{static_cast<uint8_t>(memory ? 2 : 1)};
    append_string(exports, "main");
    exports.insert(exports.end(), {0, 0});
    if (memory) {
        append_string(exports, "memory");
        exports.insert(exports.end(), {2, 0});
    }
    append_section(module, 7, exports);
    std::vector<uint8_t> body{0};
    body.insert(body.end(), code.begin(), code.end());
    std::vector<uint8_t> code_section{1};
    append_u32(code_section, static_cast<uint32_t>(body.size()));
    code_section.insert(code_section.end(), body.begin(), body.end());
    append_section(module, 10, code_section);
    if (!data.empty()) {
        std::vector<uint8_t> segment{1, 0, 0x41, 0, 0x0b};
        append_u32(segment, static_cast<uint32_t>(data.size()));
        segment.insert(segment.end(), data.begin(), data.end());
        append_section(module, 11, segment);
    }
    return module;
}

std::vector<uint8_t> module_with_loop() {
    std::vector<uint8_t> module{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00};
    append_section(module, 1, {1, 0x60, 0, 0});
    append_section(module, 3, {1, 0});
    std::vector<uint8_t> exports{1};
    append_string(exports, "spin");
    exports.insert(exports.end(), {0, 0});
    append_section(module, 7, exports);
    std::vector<uint8_t> body{0, 0x03, 0x40, 0x0c, 0, 0x0b, 0x0b};
    std::vector<uint8_t> code{1};
    append_u32(code, static_cast<uint32_t>(body.size()));
    code.insert(code.end(), body.begin(), body.end());
    append_section(module, 10, code);
    return module;
}

std::vector<uint8_t> module_with_sum_loop() {
    std::vector<uint8_t> module{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00};
    append_section(module, 1, {1, 0x60, 0, 1, 0x7f});
    append_section(module, 3, {1, 0});
    std::vector<uint8_t> exports{1};
    append_string(exports, "main");
    exports.insert(exports.end(), {0, 0});
    append_section(module, 7, exports);
    std::vector<uint8_t> body{
        1, 2, 0x7f,
        0x41, 1, 0x21, 0,
        0x41, 0, 0x21, 1,
        0x02, 0x40,
        0x03, 0x40,
        0x20, 0, 0x41, 5, 0x4b, 0x0d, 1,
        0x20, 1, 0x20, 0, 0x6a, 0x21, 1,
        0x20, 0, 0x41, 1, 0x6a, 0x21, 0,
        0x0c, 0,
        0x0b, 0x0b, 0x20, 1, 0x0b
    };
    std::vector<uint8_t> code{1};
    append_u32(code, static_cast<uint32_t>(body.size()));
    code.insert(code.end(), body.begin(), body.end());
    append_section(module, 10, code);
    return module;
}

std::vector<uint8_t> module_with_log_import() {
    std::vector<uint8_t> module{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00};
    append_section(module, 1, {2, 0x60, 2, 0x7f, 0x7f, 0, 0x60, 0, 1, 0x7f});
    std::vector<uint8_t> imports{1};
    append_string(imports, "env");
    append_string(imports, "log_info");
    imports.insert(imports.end(), {0, 0});
    append_section(module, 2, imports);
    append_section(module, 3, {1, 1});
    append_section(module, 5, {1, 0, 1});
    std::vector<uint8_t> exports{2};
    append_string(exports, "on_request");
    exports.insert(exports.end(), {0, 1});
    append_string(exports, "memory");
    exports.insert(exports.end(), {2, 0});
    append_section(module, 7, exports);
    std::vector<uint8_t> body{0, 0x41, 0, 0x41, 5, 0x10, 0, 0x41, 0, 0x0b};
    std::vector<uint8_t> code{1};
    append_u32(code, static_cast<uint32_t>(body.size()));
    code.insert(code.end(), body.begin(), body.end());
    append_section(module, 10, code);
    std::vector<uint8_t> segment{1, 0, 0x41, 0, 0x0b};
    append_u32(segment, 5);
    segment.insert(segment.end(), {'h', 'e', 'l', 'l', 'o'});
    append_section(module, 11, segment);
    return module;
}

std::vector<uint8_t> module_with_status_import() {
    std::vector<uint8_t> module{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00};
    append_section(module, 1, {
        2, 0x60, 1, 0x7f, 0, 0x60, 0, 1, 0x7f
    });
    std::vector<uint8_t> imports{1};
    append_string(imports, "env");
    append_string(imports, "set_response_status");
    imports.insert(imports.end(), {0, 0});
    append_section(module, 2, imports);
    append_section(module, 3, {1, 1});
    std::vector<uint8_t> exports{1};
    append_string(exports, "on_request");
    exports.insert(exports.end(), {0, 1});
    append_section(module, 7, exports);
    std::vector<uint8_t> body{0, 0x41, 0x93, 0x03, 0x10, 0, 0x41, 0, 0x0b};
    std::vector<uint8_t> code{1};
    append_u32(code, static_cast<uint32_t>(body.size()));
    code.insert(code.end(), body.begin(), body.end());
    append_section(module, 10, code);
    return module;
}

} // namespace

void run_wasm_tests() {
    {
        js::WasmInterpreter runtime;
        auto module = module_with_function({0x41, 40, 0x41, 2, 0x6a, 0x0b});
        assert(runtime.load_module_bytes(module.data(), module.size()));
        assert(runtime.call_function("main") == 42);
        assert(runtime.get_info().hooks.empty());
    }

    {
        js::WasmInterpreter runtime;
        auto module = module_with_function({
            0x41, 0, 0x04, 0x7f, 0x41, 1, 0x05, 0x41, 2, 0x0b, 0x0b
        });
        assert(runtime.load_module_bytes(module.data(), module.size()));
        assert(runtime.call_function("main") == 2);
    }

    {
        js::WasmInterpreter runtime;
        auto module = module_with_function({
            0x02, 0x7f, 0x41, 7, 0x0c, 0, 0x41, 99, 0x0b, 0x0b
        });
        assert(runtime.load_module_bytes(module.data(), module.size()));
        assert(runtime.call_function("main") == 7);
    }

    {
        js::WasmInterpreter runtime;
        auto module = module_with_sum_loop();
        assert(runtime.load_module_bytes(module.data(), module.size()));
        assert(runtime.call_function("main") == 15);
    }

    {
        js::WasmInterpreter runtime;
        auto module = module_with_function({
            0x41, 4, 0x41, 0xe3, 0x00, 0x36, 2, 0,
            0x41, 4, 0x28, 2, 0, 0x0b
        }, true, {42, 0, 0, 0});
        assert(runtime.load_module_bytes(module.data(), module.size()));
        assert(runtime.call_function("main") == 99);
        std::array<char, 4> bytes{};
        assert(runtime.read_memory(0, bytes.data(), bytes.size()));
        assert(bytes[0] == 42);
        assert(runtime.read_memory(4, bytes.data(), bytes.size()));
        assert(bytes[0] == 99);
        assert(!runtime.read_memory(65535, bytes.data(), bytes.size()));
    }

    {
        js::WasmInterpreter runtime;
        std::string logged;
        js::PluginHostFunctions host;
        host.log_info = [&](const std::string& value) { logged = value; };
        runtime.set_host_functions(host);
        auto module = module_with_log_import();
        assert(runtime.load_module_bytes(module.data(), module.size()));
        auto info = runtime.get_info();
        assert(info.hooks.size() == 1 && info.hooks[0] == js::PluginHook::ON_REQUEST);
        assert(runtime.call_function("on_request") == 0);
        assert(logged == "hello");
    }

    {
        auto module = module_with_status_import();
        const auto path = std::filesystem::temp_directory_path() / "justserver-test-plugin.wasm";
        {
            std::ofstream file(path, std::ios::binary);
            file.write(reinterpret_cast<const char*>(module.data()),
                       static_cast<std::streamsize>(module.size()));
        }
        js::PluginManager manager;
        assert(manager.load_plugin(path.string()));
        assert(manager.plugin_count() == 1);
        assert(manager.has_plugins_for(js::PluginHook::ON_REQUEST));

        js::HttpRequest request;
        request.method_str = "GET";
        request.uri = "/";
        js::HttpResponse response;
        auto result = manager.execute_hook(js::PluginHook::ON_REQUEST, request, response,
                                           "127.0.0.1");
        assert(result.continue_processing);
        assert(result.modified_response);
        assert(response.status_code == 403);
        assert(manager.unload_plugin(path.stem().string()));
        assert(manager.plugin_count() == 0);
        std::filesystem::remove(path);
    }

    {
        js::WasmInterpreter runtime(1024 * 1024, std::chrono::milliseconds{50});
        auto module = module_with_loop();
        assert(runtime.load_module_bytes(module.data(), module.size()));
        assert(!runtime.call_function("spin"));
        assert(runtime.last_error().find("budget") != std::string::npos);
    }

    {
        js::WasmInterpreter runtime;
        const uint8_t invalid[] = {0, 0, 0, 0};
        assert(!runtime.load_module_bytes(invalid, sizeof(invalid)));
        assert(!runtime.last_error().empty());
        assert(!runtime.call_function("missing"));
    }

    std::cout << "  [PASS] built-in WebAssembly interpreter\n";
}
