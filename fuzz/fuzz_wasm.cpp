#include "wasm_interpreter.hpp"
#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    js::WasmInterpreter runtime(1024 * 1024, std::chrono::milliseconds{10});
    if (!runtime.load_module_bytes(data, size)) return 0;
    for (const char* hook : {"on_request", "on_response", "on_route", "on_auth", "on_log"}) {
        (void)runtime.call_function(hook);
    }
    return 0;
}
