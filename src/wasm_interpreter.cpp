#include "wasm_interpreter.hpp"
#include "logger.hpp"

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <cstring>
#include <fstream>
#include <limits>
#include <type_traits>
#include <utility>

namespace js {
namespace {

constexpr uint32_t WASM_PAGE_SIZE = 65536;
constexpr uint32_t MAX_WASM32_PAGES = 65536;
constexpr uint32_t MAX_FUNCTIONS = 10000;
constexpr uint32_t MAX_LOCALS = 100000;
constexpr uint32_t MAX_TYPE_VALUES = 100000;
constexpr size_t MAX_CONTROL_DEPTH = 1024;
constexpr size_t MAX_MODULE_SIZE = 64 * 1024 * 1024;
constexpr size_t MAX_VALUE_STACK = 65536;
constexpr size_t MAX_CALL_DEPTH = 128;

enum class ValueType : uint8_t { I32 = 0x7f, I64 = 0x7e, F32 = 0x7d, F64 = 0x7c };

struct Value {
    ValueType type = ValueType::I32;
    uint64_t bits = 0;

    static Value i32(uint32_t value) { return {ValueType::I32, value}; }
    static Value i64(uint64_t value) { return {ValueType::I64, value}; }
    static Value f32(float value) { return {ValueType::F32, std::bit_cast<uint32_t>(value)}; }
    static Value f64(double value) { return {ValueType::F64, std::bit_cast<uint64_t>(value)}; }
    uint32_t as_i32() const { return static_cast<uint32_t>(bits); }
    uint64_t as_i64() const { return bits; }
    float as_f32() const { return std::bit_cast<float>(static_cast<uint32_t>(bits)); }
    double as_f64() const { return std::bit_cast<double>(bits); }
};

struct FunctionType {
    std::vector<ValueType> params;
    std::vector<ValueType> results;
};

struct Import {
    std::string module;
    std::string name;
    uint32_t type_index = 0;
};

struct FunctionBody {
    std::vector<ValueType> locals;
    std::vector<uint8_t> code;
};

struct Export {
    uint8_t kind = 0;
    uint32_t index = 0;
};

class Reader {
public:
    explicit Reader(std::span<const uint8_t> bytes, size_t position = 0)
        : bytes_(bytes), pos_(position) {}

    bool empty() const { return pos_ == bytes_.size(); }
    size_t remaining() const { return bytes_.size() - pos_; }
    size_t position() const { return pos_; }

    bool byte(uint8_t& value) {
        if (pos_ >= bytes_.size()) return false;
        value = bytes_[pos_++];
        return true;
    }

    bool bytes(size_t count, std::span<const uint8_t>& value) {
        if (count > remaining()) return false;
        value = bytes_.subspan(pos_, count);
        pos_ += count;
        return true;
    }

    bool u32(uint32_t& value) {
        uint64_t result = 0;
        for (unsigned shift = 0; shift < 35; shift += 7) {
            uint8_t part = 0;
            if (!byte(part)) return false;
            if (shift == 28 && (part & 0xf0) != 0) return false;
            result |= static_cast<uint64_t>(part & 0x7f) << shift;
            if ((part & 0x80) == 0) {
                value = static_cast<uint32_t>(result);
                return true;
            }
        }
        return false;
    }

    bool s64(int64_t& value, unsigned max_bytes = 10) {
        uint64_t result = 0;
        unsigned shift = 0;
        uint8_t part = 0;
        for (unsigned i = 0; i < max_bytes; ++i) {
            if (!byte(part)) return false;
            if (shift < 64) result |= static_cast<uint64_t>(part & 0x7f) << shift;
            shift += 7;
            if ((part & 0x80) == 0) {
                if (shift < 64 && (part & 0x40)) result |= (~uint64_t{0}) << shift;
                value = std::bit_cast<int64_t>(result);
                return true;
            }
        }
        return false;
    }

    bool string(std::string& value) {
        uint32_t length = 0;
        std::span<const uint8_t> data;
        if (!u32(length) || !bytes(length, data)) return false;
        value.assign(reinterpret_cast<const char*>(data.data()), data.size());
        return value.find('\0') == std::string::npos;
    }

private:
    std::span<const uint8_t> bytes_;
    size_t pos_ = 0;
};

bool read_value_type(Reader& reader, ValueType& type) {
    uint8_t raw = 0;
    if (!reader.byte(raw)) return false;
    switch (raw) {
        case 0x7f: type = ValueType::I32; return true;
        case 0x7e: type = ValueType::I64; return true;
        case 0x7d: type = ValueType::F32; return true;
        case 0x7c: type = ValueType::F64; return true;
        default: return false;
    }
}

bool read_limits(Reader& reader, uint32_t& minimum, uint32_t& maximum, bool& has_maximum) {
    uint32_t flags = 0;
    if (!reader.u32(flags) || flags > 1 || !reader.u32(minimum)) return false;
    has_maximum = (flags & 1) != 0;
    maximum = std::numeric_limits<uint32_t>::max();
    return !has_maximum || (reader.u32(maximum) && maximum >= minimum);
}

bool skip_instruction_immediate(Reader& reader, uint8_t opcode) {
    uint32_t ignored = 0;
    int64_t signed_ignored = 0;
    std::string ignored_string;
    switch (opcode) {
        case 0x02: case 0x03: case 0x04: {
            uint8_t block_type = 0;
            if (!reader.byte(block_type)) return false;
            return block_type == 0x40 || block_type == 0x7f || block_type == 0x7e ||
                   block_type == 0x7d || block_type == 0x7c;
        }
        case 0x0c: case 0x0d: case 0x10:
        case 0x20: case 0x21: case 0x22:
        case 0x23: case 0x24:
        case 0x3f: case 0x40:
            return reader.u32(ignored);
        case 0x0e: {
            uint32_t count = 0;
            if (!reader.u32(count) || count > MAX_FUNCTIONS) return false;
            for (uint32_t i = 0; i <= count; ++i) {
                if (!reader.u32(ignored)) return false;
            }
            return true;
        }
        case 0x11:
            return reader.u32(ignored) && reader.u32(ignored);
        case 0x28: case 0x29: case 0x2a: case 0x2b:
        case 0x2c: case 0x2d: case 0x2e: case 0x2f:
        case 0x30: case 0x31: case 0x32: case 0x33:
        case 0x34: case 0x35:
        case 0x36: case 0x37: case 0x38: case 0x39:
        case 0x3a: case 0x3b: case 0x3c: case 0x3d: case 0x3e:
            return reader.u32(ignored) && reader.u32(ignored);
        case 0x41: case 0x42:
            return reader.s64(signed_ignored, opcode == 0x41 ? 5 : 10);
        case 0x43: {
            std::span<const uint8_t> bytes;
            return reader.bytes(4, bytes);
        }
        case 0x44: {
            std::span<const uint8_t> bytes;
            return reader.bytes(8, bytes);
        }
        default:
            return true;
    }
}

bool find_control_targets(const std::vector<uint8_t>& code,
                          std::vector<size_t>& matching,
                          std::vector<size_t>& alternate,
                          std::string& error) {
    matching.assign(code.size(), code.size());
    alternate.assign(code.size(), code.size());
    Reader reader(code);
    std::vector<size_t> controls;
    std::vector<bool> has_else;
    while (!reader.empty()) {
        size_t at = reader.position();
        uint8_t opcode = 0;
        if (!reader.byte(opcode)) return false;
        if (opcode == 0x02 || opcode == 0x03 || opcode == 0x04) {
            uint8_t block_type = 0;
            if (!reader.byte(block_type) ||
                !(block_type == 0x40 || block_type == 0x7f || block_type == 0x7e ||
                  block_type == 0x7d || block_type == 0x7c)) {
                error = "unsupported or malformed block type";
                return false;
            }
            controls.push_back(at);
            if (controls.size() > MAX_CONTROL_DEPTH) {
                error = "maximum structured-control depth exceeded";
                return false;
            }
            has_else.push_back(false);
        } else if (opcode == 0x05) {
            if (controls.empty() || has_else.back()) {
                error = "unexpected else opcode";
                return false;
            }
            has_else.back() = true;
            alternate[controls.back()] = at;
        } else if (opcode == 0x0b) {
            if (controls.empty()) {
                if (!reader.empty()) {
                    error = "instructions after function end";
                    return false;
                }
                matching[at] = at;
                continue;
            }
            auto start = controls.back();
            controls.pop_back();
            has_else.pop_back();
            matching[start] = at;
            if (alternate[start] != code.size()) matching[alternate[start]] = at;
        } else if (!skip_instruction_immediate(reader, opcode)) {
            error = "malformed instruction immediate";
            return false;
        }
    }
    if (!controls.empty()) {
        error = "unterminated control block";
        return false;
    }
    return true;
}

} // namespace

struct WasmInterpreter::Impl {
    size_t max_memory_bytes;
    std::chrono::milliseconds timeout;
    std::vector<FunctionType> types;
    std::vector<Import> imports;
    std::vector<uint32_t> function_types;
    std::vector<FunctionBody> bodies;
    std::unordered_map<std::string, Export> exports;
    std::vector<uint8_t> memory;
    uint32_t memory_max_pages = 0;
    bool has_memory = false;
    bool module_loaded = false;
    PluginHostFunctions host;
    std::string error;
    std::string module_name = "wasm-module";

    explicit Impl(size_t max_bytes, std::chrono::milliseconds max_time)
        : max_memory_bytes(std::max<size_t>(WASM_PAGE_SIZE, max_bytes)),
          timeout(std::max(std::chrono::milliseconds{1}, max_time)) {}

    void fail(std::string message) { error = std::move(message); }

    void reset() {
        types.clear();
        imports.clear();
        function_types.clear();
        bodies.clear();
        exports.clear();
        memory.clear();
        has_memory = false;
        module_loaded = false;
        memory_max_pages = static_cast<uint32_t>(
            std::min<size_t>(max_memory_bytes / WASM_PAGE_SIZE,
                            MAX_WASM32_PAGES));
        module_name = "wasm-module";
        error.clear();
    }

    bool load(std::span<const uint8_t> bytes) {
        reset();
        if (bytes.size() > MAX_MODULE_SIZE) {
            fail("WebAssembly module exceeds the 64 MiB input limit");
            return false;
        }
        if (bytes.size() < 8 || bytes[0] != 0x00 || bytes[1] != 0x61 ||
            bytes[2] != 0x73 || bytes[3] != 0x6d ||
            bytes[4] != 0x01 || bytes[5] != 0x00 ||
            bytes[6] != 0x00 || bytes[7] != 0x00) {
            fail("invalid WebAssembly magic or unsupported version");
            return false;
        }

        Reader reader(bytes.subspan(8));
        uint8_t previous_section = 0;
        while (!reader.empty()) {
            uint8_t section_id = 0;
            uint32_t section_size = 0;
            std::span<const uint8_t> payload;
            if (!reader.byte(section_id) || !reader.u32(section_size) ||
                !reader.bytes(section_size, payload)) {
                fail("truncated section header or payload");
                return false;
            }
            if (section_id == 0) continue;
            if (section_id > 11 || section_id <= previous_section) {
                fail("invalid, duplicate, or unsupported section ordering");
                return false;
            }
            previous_section = section_id;
            Reader section(payload);
            uint32_t count = 0;
            switch (section_id) {
                case 1: {
                    if (!section.u32(count) || count > MAX_FUNCTIONS) {
                        fail("invalid type section size");
                        return false;
                    }
                    uint64_t total_values = 0;
                    for (uint32_t i = 0; i < count; ++i) {
                        uint8_t form = 0;
                        uint32_t n = 0;
                        FunctionType type;
                        if (!section.byte(form) || form != 0x60 ||
                            !section.u32(n) || n > MAX_TYPE_VALUES ||
                            total_values + n > MAX_TYPE_VALUES) {
                            fail("invalid function type");
                            return false;
                        }
                        for (uint32_t j = 0; j < n; ++j) {
                            ValueType value_type;
                            if (!read_value_type(section, value_type)) {
                                fail("unsupported parameter type");
                                return false;
                            }
                            type.params.push_back(value_type);
                        }
                        total_values += n;
                        if (!section.u32(n) || n > 1) {
                            fail("multi-value function results are not supported");
                            return false;
                        }
                        total_values += n;
                        if (total_values > MAX_TYPE_VALUES) {
                            fail("type section exceeds the value count limit");
                            return false;
                        }
                        for (uint32_t j = 0; j < n; ++j) {
                            ValueType value_type;
                            if (!read_value_type(section, value_type)) {
                                fail("unsupported result type");
                                return false;
                            }
                            type.results.push_back(value_type);
                        }
                        types.push_back(std::move(type));
                    }
                    break;
                }
                case 2:
                    if (!section.u32(count) || count > MAX_FUNCTIONS) {
                        fail("invalid import section size");
                        return false;
                    }
                    for (uint32_t i = 0; i < count; ++i) {
                        Import import;
                        uint8_t kind = 0;
                        if (!section.string(import.module) || !section.string(import.name) ||
                            !section.byte(kind) || kind != 0 ||
                            !section.u32(import.type_index) || import.type_index >= types.size()) {
                            fail("only function imports with valid types are supported");
                            return false;
                        }
                        if ((import.module != "env" && import.module != "justserver") ||
                            !supported_host_import(import.name)) {
                            fail("unsupported host import: " + import.module + "." + import.name);
                            return false;
                        }
                        if (!valid_host_import_type(import.name, types[import.type_index])) {
                            fail("invalid function signature for host import: " + import.name);
                            return false;
                        }
                        imports.push_back(std::move(import));
                    }
                    break;
                case 3:
                    if (!section.u32(count) || count > MAX_FUNCTIONS) {
                        fail("invalid function section size");
                        return false;
                    }
                    for (uint32_t i = 0; i < count; ++i) {
                        uint32_t type_index = 0;
                        if (!section.u32(type_index) || type_index >= types.size()) {
                            fail("function references an invalid type");
                            return false;
                        }
                        function_types.push_back(type_index);
                    }
                    break;
                case 5: {
                    if (!section.u32(count) || count > 1) {
                        fail("at most one linear memory is supported");
                        return false;
                    }
                    if (count == 1) {
                        uint32_t minimum = 0, maximum = 0;
                        bool has_maximum = false;
                        if (!read_limits(section, minimum, maximum, has_maximum) ||
                            minimum > memory_max_pages ||
                            (has_maximum && maximum > memory_max_pages)) {
                            fail("linear memory exceeds configured limit or has invalid bounds");
                            return false;
                        }
                        has_memory = true;
                        memory_max_pages = has_maximum ? maximum : memory_max_pages;
                        memory.resize(static_cast<size_t>(minimum) * WASM_PAGE_SIZE);
                    }
                    break;
                }
                case 7:
                    if (!section.u32(count) || count > MAX_FUNCTIONS) {
                        fail("invalid export section size");
                        return false;
                    }
                    for (uint32_t i = 0; i < count; ++i) {
                        std::string name;
                        Export value;
                        if (!section.string(name) || !section.byte(value.kind) ||
                            !section.u32(value.index) || !exports.emplace(name, value).second) {
                            fail("invalid or duplicate export");
                            return false;
                        }
                    }
                    break;
                case 10: {
                    if (!section.u32(count) || count != function_types.size()) {
                        fail("code/function section size mismatch");
                        return false;
                    }
                    uint64_t total_locals = 0;
                    for (uint32_t i = 0; i < count; ++i) {
                        uint32_t body_size = 0;
                        std::span<const uint8_t> raw_body;
                        if (!section.u32(body_size) || !section.bytes(body_size, raw_body)) {
                            fail("truncated function body");
                            return false;
                        }
                        Reader body_reader(raw_body);
                        uint32_t local_groups = 0;
                        FunctionBody body;
                        if (!body_reader.u32(local_groups) || local_groups > MAX_LOCALS) {
                            fail("invalid local declarations");
                            return false;
                        }
                        for (uint32_t group = 0; group < local_groups; ++group) {
                            uint32_t local_count = 0;
                            ValueType type;
                            if (!body_reader.u32(local_count) ||
                                body.locals.size() + local_count > MAX_LOCALS ||
                                total_locals + local_count > MAX_TYPE_VALUES ||
                                !read_value_type(body_reader, type)) {
                                fail("invalid local declaration");
                                return false;
                            }
                            body.locals.insert(body.locals.end(), local_count, type);
                            total_locals += local_count;
                        }
                        std::span<const uint8_t> code;
                        if (!body_reader.bytes(body_reader.remaining(), code) || code.empty() ||
                            code.back() != 0x0b) {
                            fail("function body lacks end opcode");
                            return false;
                        }
                        body.code.assign(code.begin(), code.end());
                        std::vector<size_t> matching, alternate;
                        if (!find_control_targets(body.code, matching, alternate, error)) return false;
                        bodies.push_back(std::move(body));
                    }
                    break;
                }
                case 11:
                    if (!section.u32(count) || count > MAX_FUNCTIONS) {
                        fail("invalid data section size");
                        return false;
                    }
                    for (uint32_t i = 0; i < count; ++i) {
                        uint32_t mode = 0;
                        if (!section.u32(mode) || mode != 0 || !has_memory) {
                            fail("only active data segments for memory zero are supported");
                            return false;
                        }
                        uint8_t opcode = 0;
                        int64_t offset = 0;
                        uint32_t length = 0;
                        std::span<const uint8_t> data;
                        if (!section.byte(opcode) || opcode != 0x41 ||
                            !section.s64(offset, 5) || offset < 0 ||
                            !section.byte(opcode) || opcode != 0x0b ||
                            !section.u32(length) || !section.bytes(length, data) ||
                            static_cast<uint64_t>(offset) + length > memory.size()) {
                            fail("invalid or out-of-bounds data segment");
                            return false;
                        }
                        std::copy(data.begin(), data.end(),
                                  memory.begin() + static_cast<size_t>(offset));
                    }
                    break;
                default:
                    fail("module uses an unsupported WebAssembly section");
                    return false;
            }
            if (!section.empty()) {
                fail("trailing bytes in section");
                return false;
            }
        }

        if (bodies.size() != function_types.size()) {
            fail("module is missing function bodies");
            return false;
        }
        for (const auto& [name, exp] : exports) {
            if ((exp.kind == 0 && exp.index >= imports.size() + function_types.size()) ||
                (exp.kind == 2 && (!has_memory || exp.index != 0)) ||
                (exp.kind != 0 && exp.kind != 2)) {
                fail("export references an unsupported or invalid item: " + name);
                return false;
            }
        }
        module_loaded = true;
        return true;
    }

    static bool supported_host_import(std::string_view name) {
        static constexpr std::array names{
            std::string_view{"get_request_method"}, std::string_view{"get_request_uri"},
            std::string_view{"get_request_body"}, std::string_view{"get_client_ip"},
            std::string_view{"get_request_header"}, std::string_view{"set_request_header"},
            std::string_view{"set_response_status"}, std::string_view{"set_response_header"},
            std::string_view{"set_response_body"}, std::string_view{"log_info"},
            std::string_view{"log_error"}, std::string_view{"kv_get"},
            std::string_view{"kv_set"}
        };
        return std::find(names.begin(), names.end(), name) != names.end();
    }

    static bool valid_host_import_type(std::string_view name, const FunctionType& type) {
        size_t parameter_count = 0;
        bool returns_length = false;
        if (name == "get_request_method" || name == "get_request_uri" ||
            name == "get_request_body" || name == "get_client_ip") {
            parameter_count = 2;
            returns_length = true;
        } else if (name == "get_request_header" || name == "kv_get") {
            parameter_count = 4;
            returns_length = true;
        } else if (name == "set_request_header" || name == "set_response_header" ||
                   name == "kv_set") {
            parameter_count = 4;
        } else if (name == "set_response_status") {
            parameter_count = 1;
        } else {
            parameter_count = 2;
        }
        if (type.params.size() != parameter_count ||
            type.results.size() != static_cast<size_t>(returns_length)) {
            return false;
        }
        return std::all_of(type.params.begin(), type.params.end(),
                           [](ValueType value) { return value == ValueType::I32; }) &&
               (type.results.empty() || type.results[0] == ValueType::I32);
    }

    bool range(uint32_t offset, size_t length) const {
        return static_cast<size_t>(offset) <= memory.size() &&
               length <= memory.size() - static_cast<size_t>(offset);
    }

    std::optional<Value> invoke(uint32_t function_index, std::vector<Value> args,
                                size_t depth, size_t& fuel,
                                std::chrono::steady_clock::time_point deadline);

    std::optional<Value> invoke_host(const Import& import, const FunctionType& type,
                                     const std::vector<Value>& args);

    std::optional<Value> execute(const FunctionBody& body, const FunctionType& type,
                                 std::vector<Value> locals, size_t depth, size_t& fuel,
                                 std::chrono::steady_clock::time_point deadline);

    std::optional<Value> call_export(std::string_view name) {
        error.clear();
        if (!module_loaded) {
            fail("no WebAssembly module is loaded");
            return std::nullopt;
        }
        auto it = exports.find(std::string(name));
        if (it == exports.end() || it->second.kind != 0) {
            fail("function export not found: " + std::string(name));
            return std::nullopt;
        }
        const auto index = it->second.index;
        if (index >= imports.size() + function_types.size()) {
            fail("invalid function export index");
            return std::nullopt;
        }
        size_t fuel = 1'000'000;
        auto deadline = std::chrono::steady_clock::now() + timeout;
        auto result = invoke(index, {}, 0, fuel, deadline);
        if (!result && error.empty()) fail("function invocation failed");
        return result;
    }
};

namespace {

std::optional<Value> call_host_callback(const PluginHostFunctions& host,
                                        const Import& import, const FunctionType& type,
                                        const std::vector<Value>& args,
                                        std::vector<uint8_t>& memory,
                                        std::string& error) {
    auto get_string = [&](uint32_t offset, uint32_t length) -> std::optional<std::string> {
        if (static_cast<size_t>(offset) > memory.size() ||
            static_cast<size_t>(length) > memory.size() - offset) {
            error = "host import string points outside linear memory";
            return std::nullopt;
        }
        return std::string(reinterpret_cast<const char*>(memory.data() + offset), length);
    };
    auto write_string = [&](const std::string& value, uint32_t offset,
                            uint32_t capacity) -> std::optional<Value> {
        size_t copied = std::min<size_t>(value.size(), capacity);
        if (static_cast<size_t>(offset) > memory.size() ||
            copied > memory.size() - offset) {
            error = "host import output points outside linear memory";
            return std::nullopt;
        }
        if (copied != 0) std::memcpy(memory.data() + offset, value.data(), copied);
        if (!type.results.empty()) return Value::i32(static_cast<uint32_t>(value.size()));
        return Value::i32(0);
    };
    auto i32arg = [&](size_t i) { return args[i].as_i32(); };
    auto check_args = [&](size_t count) {
        if (args.size() == count) return true;
        error = "incorrect host import signature: " + import.name;
        return false;
    };

    std::optional<std::string> string_result;
    if (import.name == "get_request_method" || import.name == "get_request_uri" ||
        import.name == "get_request_body" || import.name == "get_client_ip") {
        if (!check_args(2)) return std::nullopt;
        if (import.name == "get_request_method" && host.get_request_method)
            string_result = host.get_request_method();
        else if (import.name == "get_request_uri" && host.get_request_uri)
            string_result = host.get_request_uri();
        else if (import.name == "get_request_body" && host.get_request_body)
            string_result = host.get_request_body();
        else if (import.name == "get_client_ip" && host.get_client_ip)
            string_result = host.get_client_ip();
        return write_string(string_result.value_or(""), i32arg(0), i32arg(1));
    }
    if (import.name == "get_request_header") {
        if (!check_args(4)) return std::nullopt;
        auto key = get_string(i32arg(0), i32arg(1));
        if (!key) return std::nullopt;
        if (host.get_request_header) string_result = host.get_request_header(*key);
        return write_string(string_result.value_or(""), i32arg(2), i32arg(3));
    }
    if (import.name == "set_request_header" || import.name == "set_response_header" ||
        import.name == "kv_set") {
        if (!check_args(4)) return std::nullopt;
        auto key = get_string(i32arg(0), i32arg(1));
        auto value = get_string(i32arg(2), i32arg(3));
        if (!key || !value) return std::nullopt;
        if (import.name == "set_request_header" && host.set_request_header)
            host.set_request_header(*key, *value);
        else if (import.name == "set_response_header" && host.set_response_header)
            host.set_response_header(*key, *value);
        else if (import.name == "kv_set" && host.kv_set)
            host.kv_set(*key, *value);
        return type.results.empty() ? std::nullopt : std::optional<Value>(Value::i32(0));
    }
    if (import.name == "set_response_status") {
        if (!check_args(1)) return std::nullopt;
        if (host.set_response_status) host.set_response_status(static_cast<int32_t>(i32arg(0)));
        return type.results.empty() ? std::nullopt : std::optional<Value>(Value::i32(0));
    }
    if (import.name == "set_response_body" || import.name == "log_info" ||
        import.name == "log_error") {
        if (!check_args(2)) return std::nullopt;
        auto value = get_string(i32arg(0), i32arg(1));
        if (!value) return std::nullopt;
        if (import.name == "set_response_body" && host.set_response_body)
            host.set_response_body(*value);
        else if (import.name == "log_info" && host.log_info)
            host.log_info(*value);
        else if (import.name == "log_error" && host.log_error)
            host.log_error(*value);
        return type.results.empty() ? std::nullopt : std::optional<Value>(Value::i32(0));
    }
    if (import.name == "kv_get") {
        if (!check_args(4)) return std::nullopt;
        auto key = get_string(i32arg(0), i32arg(1));
        if (!key) return std::nullopt;
        auto value = host.kv_get ? host.kv_get(*key) : std::nullopt;
        if (!value) return type.results.empty() ? std::nullopt
                                                : std::optional<Value>(Value::i32(0));
        return write_string(*value, i32arg(2), i32arg(3));
    }

    error = "unimplemented host import: " + import.name;
    return std::nullopt;
}

} // namespace

std::optional<Value> WasmInterpreter::Impl::invoke_host(const Import& import,
                                                        const FunctionType& type,
                                                        const std::vector<Value>& args) {
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i].type != type.params[i]) {
            fail("host import argument type mismatch: " + import.name);
            return std::nullopt;
        }
    }
    std::string host_error;
    auto result = call_host_callback(host, import, type, args, memory, host_error);
    if (!host_error.empty()) fail(std::move(host_error));
    if (result && !type.results.empty() &&
        (type.results.size() != 1 || result->type != type.results[0])) {
        fail("host import result type mismatch: " + import.name);
        return std::nullopt;
    }
    if (type.results.empty()) return Value::i32(0);
    return result;
}

std::optional<Value> WasmInterpreter::Impl::invoke(
    uint32_t function_index, std::vector<Value> args, size_t depth, size_t& fuel,
    std::chrono::steady_clock::time_point deadline) {
    if (depth >= MAX_CALL_DEPTH) {
        fail("maximum WebAssembly call depth exceeded");
        return std::nullopt;
    }
    if (function_index < imports.size()) {
        const auto& import = imports[function_index];
        return invoke_host(import, types[import.type_index], args);
    }
    size_t body_index = function_index - imports.size();
    if (body_index >= bodies.size()) {
        fail("call references an invalid function");
        return std::nullopt;
    }
    const auto& type = types[function_types[body_index]];
    if (args.size() != type.params.size()) {
        fail("function called with wrong number of arguments");
        return std::nullopt;
    }
    for (size_t i = 0; i < args.size(); ++i) {
        if (args[i].type != type.params[i]) {
            fail("function called with wrong argument type");
            return std::nullopt;
        }
    }
    auto locals = std::move(args);
    for (ValueType local_type : bodies[body_index].locals) {
        locals.push_back({local_type, 0});
    }
    return execute(bodies[body_index], type, std::move(locals), depth, fuel, deadline);
}

std::optional<Value> WasmInterpreter::Impl::execute(
    const FunctionBody& body, const FunctionType& type, std::vector<Value> locals,
    size_t depth, size_t& fuel, std::chrono::steady_clock::time_point deadline) {
    Reader code(body.code);
    std::vector<Value> stack;
    struct Control {
        uint8_t kind;
        size_t start;
        size_t end;
        size_t alternate;
        size_t height;
        bool has_result;
        ValueType result_type;
    };
    std::vector<Control> controls;

    std::vector<size_t> matching, alternate;
    if (!find_control_targets(body.code, matching, alternate, error)) return std::nullopt;

    auto pop = [&](ValueType expected, Value& output) {
        if (stack.empty() || stack.back().type != expected) {
            fail("operand stack underflow or type mismatch");
            return false;
        }
        output = stack.back();
        stack.pop_back();
        return true;
    };
    auto push = [&](Value value) {
        if (stack.size() >= MAX_VALUE_STACK) {
            fail("operand stack limit exceeded");
            return false;
        }
        stack.push_back(value);
        return true;
    };
    auto read_u32 = [&](uint32_t& value) { return code.u32(value); };
    auto branch = [&](uint32_t depth_value) -> std::optional<int> {
        if (depth_value >= controls.size()) {
            fail("branch depth is out of range");
            return std::nullopt;
        }
        size_t target_index = controls.size() - 1 - depth_value;
        Control target = controls[target_index];
        Value result;
        if (target.has_result && !pop(target.result_type, result)) return std::nullopt;
        if (stack.size() < target.height) {
            fail("branch invalidates the operand stack");
            return std::nullopt;
        }
        stack.resize(target.height);
        if (target.has_result) stack.push_back(result);
        if (target.kind == 0xff) return 2;
        if (target.kind == 0x03) {
            controls.resize(target_index + 1);
            code = Reader(body.code, target.start);
            return 1;
        }
        controls.resize(target_index);
        code = Reader(body.code, target.end + 1);
        return 1;
    };

    controls.push_back({0xff, 0, body.code.size() - 1, body.code.size() - 1,
                        0, !type.results.empty(),
                        type.results.empty() ? ValueType::I32 : type.results[0]});

    while (!code.empty()) {
        if (fuel == 0 || std::chrono::steady_clock::now() > deadline) {
            fail("WebAssembly execution budget exceeded");
            return std::nullopt;
        }
        --fuel;
        size_t opcode_position = code.position();
        uint8_t opcode = 0;
        if (!code.byte(opcode)) break;
        uint32_t immediate = 0;
        int64_t signed_immediate = 0;
        Value a, b;
        switch (opcode) {
            case 0x00:
                fail("WebAssembly unreachable instruction executed");
                return std::nullopt;
            case 0x01:
                break;
            case 0x02: case 0x03: case 0x04: {
                uint8_t block_type = 0;
                if (!code.byte(block_type)) {
                    fail("truncated block type");
                    return std::nullopt;
                }
                bool has_result = block_type != 0x40;
                ValueType result_type = has_result ? static_cast<ValueType>(block_type)
                                                   : ValueType::I32;
                bool condition = true;
                if (opcode == 0x04) {
                    if (!pop(ValueType::I32, a)) return std::nullopt;
                    condition = a.as_i32() != 0;
                }
                size_t end = matching[opcode_position];
                size_t alt = alternate[opcode_position];
                if (end >= body.code.size()) {
                    fail("invalid block structure");
                    return std::nullopt;
                }
                if (opcode == 0x04 && !condition) {
                    if (alt != body.code.size()) {
                        controls.push_back({opcode, code.position(), end, alt,
                                            stack.size(), has_result, result_type});
                        code = Reader(body.code, alt + 1);
                    } else {
                        code = Reader(body.code, end + 1);
                    }
                } else {
                    controls.push_back({opcode, code.position(), end, alt, stack.size(),
                                        has_result, result_type});
                }
                break;
            }
            case 0x05: {
                if (controls.empty() || controls.back().kind != 0x04 ||
                    controls.back().alternate != opcode_position) {
                    fail("unexpected else");
                    return std::nullopt;
                }
                auto control = controls.back();
                controls.pop_back();
                if (control.has_result && !pop(control.result_type, a)) return std::nullopt;
                if (stack.size() < control.height) {
                    fail("else invalidates the operand stack");
                    return std::nullopt;
                }
                stack.resize(control.height);
                if (control.has_result) stack.push_back(a);
                code = Reader(body.code, control.end + 1);
                break;
            }
            case 0x0b: {
                if (controls.empty()) {
                    fail("unexpected end");
                    return std::nullopt;
                }
                auto control = controls.back();
                controls.pop_back();
                if (control.has_result && !pop(control.result_type, a)) return std::nullopt;
                if (stack.size() < control.height) {
                    fail("end invalidates the operand stack");
                    return std::nullopt;
                }
                stack.resize(control.height);
                if (control.has_result) stack.push_back(a);
                if (control.kind == 0xff) {
                    if (type.results.empty()) {
                        if (!stack.empty()) {
                            fail("function leaves values on the operand stack");
                            return std::nullopt;
                        }
                        return Value::i32(0);
                    }
                    if (!pop(type.results[0], a)) return std::nullopt;
                    if (!stack.empty()) {
                        fail("function leaves values on the operand stack");
                        return std::nullopt;
                    }
                    return a;
                }
                break;
            }
            case 0x0c: case 0x0d: {
                if (!read_u32(immediate)) {
                    fail("truncated branch depth");
                    return std::nullopt;
                }
                if (opcode == 0x0d) {
                    if (!pop(ValueType::I32, a)) return std::nullopt;
                    if (a.as_i32() == 0) break;
                }
                auto status = branch(immediate);
                if (!status) return std::nullopt;
                if (*status == 2) {
                    if (type.results.empty()) {
                        if (!stack.empty()) {
                            fail("function branch leaves values on the operand stack");
                            return std::nullopt;
                        }
                        return Value::i32(0);
                    }
                    if (!pop(type.results[0], a)) return std::nullopt;
                    if (!stack.empty()) {
                        fail("function branch leaves values on the operand stack");
                        return std::nullopt;
                    }
                    return a;
                }
                break;
            }
            case 0x0e: {
                uint32_t count = 0;
                if (!code.u32(count) || count > MAX_FUNCTIONS) {
                    fail("invalid br_table");
                    return std::nullopt;
                }
                std::vector<uint32_t> labels(count + 1);
                for (auto& label : labels) {
                    if (!code.u32(label)) {
                        fail("truncated br_table");
                        return std::nullopt;
                    }
                }
                if (!pop(ValueType::I32, a)) return std::nullopt;
                uint32_t index = a.as_i32();
                auto status = branch(labels[index < count ? index : count]);
                if (!status) return std::nullopt;
                if (*status == 2) {
                    if (type.results.empty()) {
                        if (!stack.empty()) {
                            fail("function branch leaves values on the operand stack");
                            return std::nullopt;
                        }
                        return Value::i32(0);
                    }
                    if (!pop(type.results[0], a)) return std::nullopt;
                    if (!stack.empty()) {
                        fail("function branch leaves values on the operand stack");
                        return std::nullopt;
                    }
                    return a;
                }
                break;
            }
            case 0x0f:
                if (type.results.empty()) {
                    if (!stack.empty()) {
                        fail("return leaves values on the operand stack");
                        return std::nullopt;
                    }
                    return Value::i32(0);
                }
                if (!pop(type.results[0], a)) return std::nullopt;
                if (!stack.empty()) {
                    fail("return leaves values on the operand stack");
                    return std::nullopt;
                }
                return a;
            case 0x10: {
                uint32_t index = 0;
                if (!code.u32(index) || index >= imports.size() + function_types.size()) {
                    fail("call references invalid function");
                    return std::nullopt;
                }
                const auto& called_type = types[index < imports.size()
                    ? imports[index].type_index : function_types[index - imports.size()]];
                std::vector<Value> args(called_type.params.size());
                for (size_t i = args.size(); i > 0; --i) {
                    if (!pop(called_type.params[i - 1], args[i - 1])) return std::nullopt;
                }
                auto result = invoke(index, std::move(args), depth + 1, fuel, deadline);
                if (!result) {
                    if (!called_type.results.empty()) return std::nullopt;
                    if (!error.empty()) return std::nullopt;
                } else if (!called_type.results.empty() && !push(*result)) {
                    return std::nullopt;
                }
                break;
            }
            case 0x1a:
                if (stack.empty()) {
                    fail("drop on empty operand stack");
                    return std::nullopt;
                }
                stack.pop_back();
                break;
            case 0x1b: {
                if (!pop(ValueType::I32, a) || stack.size() < 2) {
                    if (error.empty()) fail("select operand stack underflow");
                    return std::nullopt;
                }
                b = stack.back(); stack.pop_back();
                Value c = stack.back(); stack.pop_back();
                if (b.type != c.type) {
                    fail("select operands have different types");
                    return std::nullopt;
                }
                if (!push(a.as_i32() != 0 ? c : b)) return std::nullopt;
                break;
            }
            case 0x20: case 0x21: case 0x22: {
                if (!code.u32(immediate) || immediate >= locals.size()) {
                    fail("local index out of range");
                    return std::nullopt;
                }
                if (opcode == 0x20) {
                    if (!push(locals[immediate])) return std::nullopt;
                } else {
                    if (stack.empty() || stack.back().type != locals[immediate].type) {
                        fail("local assignment type mismatch");
                        return std::nullopt;
                    }
                    locals[immediate] = stack.back();
                    if (opcode == 0x21) stack.pop_back();
                }
                break;
            }
            case 0x28: case 0x29: case 0x2a: case 0x2b:
            case 0x2c: case 0x2d:
            case 0x2e: case 0x2f: case 0x30: case 0x31:
            case 0x32: case 0x33: case 0x34: case 0x35: {
                uint32_t alignment = 0, offset = 0;
                if (!code.u32(alignment) || !code.u32(offset) ||
                    !pop(ValueType::I32, a)) {
                    fail("invalid memory load");
                    return std::nullopt;
                }
                uint64_t address64 = static_cast<uint64_t>(a.as_i32()) + offset;
                size_t width = (opcode == 0x28 || opcode == 0x2a) ? 4 :
                               (opcode == 0x29 || opcode == 0x2b) ? 8 :
                               (opcode == 0x2c || opcode == 0x2d) ? 1 :
                               (opcode == 0x2e || opcode == 0x2f) ? 2 :
                               (opcode == 0x30 || opcode == 0x31) ? 1 :
                               (opcode == 0x32 || opcode == 0x33) ? 2 : 4;
                if (address64 > std::numeric_limits<uint32_t>::max() ||
                    !has_memory || !range(static_cast<uint32_t>(address64), width)) {
                    fail("out-of-bounds memory load");
                    return std::nullopt;
                }
                uint64_t raw = 0;
                std::memcpy(&raw, memory.data() + static_cast<size_t>(address64), width);
                if (opcode == 0x28) {
                    if (!push(Value::i32(static_cast<uint32_t>(raw)))) return std::nullopt;
                } else if (opcode == 0x29) {
                    if (!push(Value::i64(raw))) return std::nullopt;
                } else if (opcode == 0x2a) {
                    if (!push(Value{ValueType::F32, static_cast<uint32_t>(raw)}))
                        return std::nullopt;
                } else if (opcode == 0x2b) {
                    if (!push(Value{ValueType::F64, raw})) return std::nullopt;
                } else if (opcode == 0x2c || opcode == 0x2d) {
                    uint8_t value = static_cast<uint8_t>(raw);
                    uint32_t result = opcode == 0x2c
                        ? static_cast<uint32_t>(static_cast<int32_t>(static_cast<int8_t>(value)))
                        : value;
                    if (!push(Value::i32(result))) return std::nullopt;
                } else if (opcode == 0x2e || opcode == 0x2f) {
                    uint16_t value = static_cast<uint16_t>(raw);
                    uint32_t result = opcode == 0x2e
                        ? static_cast<uint32_t>(static_cast<int32_t>(static_cast<int16_t>(value)))
                        : value;
                    if (!push(Value::i32(result))) return std::nullopt;
                } else if (opcode == 0x30 || opcode == 0x31) {
                    uint8_t value = static_cast<uint8_t>(raw);
                    uint64_t result = opcode == 0x30
                        ? static_cast<uint64_t>(static_cast<int64_t>(static_cast<int8_t>(value)))
                        : value;
                    if (!push(Value::i64(result))) return std::nullopt;
                } else if (opcode == 0x32 || opcode == 0x33) {
                    uint16_t value = static_cast<uint16_t>(raw);
                    uint64_t result = opcode == 0x32
                        ? static_cast<uint64_t>(static_cast<int64_t>(static_cast<int16_t>(value)))
                        : value;
                    if (!push(Value::i64(result))) return std::nullopt;
                } else if (opcode == 0x34 || opcode == 0x35) {
                    uint32_t value = static_cast<uint32_t>(raw);
                    uint64_t result = opcode == 0x34
                        ? static_cast<uint64_t>(static_cast<int64_t>(static_cast<int32_t>(value)))
                        : value;
                    if (!push(Value::i64(result))) return std::nullopt;
                }
                break;
            }
            case 0x36: case 0x37: case 0x38: case 0x39:
            case 0x3a: case 0x3b: case 0x3c: case 0x3d: case 0x3e: {
                uint32_t alignment = 0, offset = 0;
                if (!code.u32(alignment) || !code.u32(offset)) {
                    fail("invalid memory store immediate");
                    return std::nullopt;
                }
                ValueType value_type = opcode == 0x37 || opcode >= 0x3c
                    ? ValueType::I64 : opcode == 0x38 ? ValueType::F32
                    : opcode == 0x39 ? ValueType::F64 : ValueType::I32;
                if (!pop(value_type, b) || !pop(ValueType::I32, a)) return std::nullopt;
                uint64_t address64 = static_cast<uint64_t>(a.as_i32()) + offset;
                size_t width = opcode == 0x36 || opcode == 0x38 ? 4 :
                               opcode == 0x37 || opcode == 0x39 ? 8 :
                               opcode == 0x3a || opcode == 0x3c ? 1 :
                               opcode == 0x3b || opcode == 0x3d ? 2 : 4;
                if (address64 > std::numeric_limits<uint32_t>::max() ||
                    !has_memory || !range(static_cast<uint32_t>(address64), width)) {
                    fail("out-of-bounds memory store");
                    return std::nullopt;
                }
                uint64_t raw = b.bits;
                std::memcpy(memory.data() + static_cast<size_t>(address64), &raw, width);
                break;
            }
            case 0x3f: {
                uint32_t memory_index = 0;
                if (!code.u32(memory_index) || memory_index != 0 || !has_memory) {
                    fail("memory.size requires memory zero");
                    return std::nullopt;
                }
                if (!push(Value::i32(static_cast<uint32_t>(memory.size() / WASM_PAGE_SIZE))))
                    return std::nullopt;
                break;
            }
            case 0x40: {
                uint32_t memory_index = 0;
                if (!code.u32(memory_index) || memory_index != 0 ||
                    !pop(ValueType::I32, a) || !has_memory) {
                    fail("invalid memory.grow");
                    return std::nullopt;
                }
                uint32_t old_pages = static_cast<uint32_t>(memory.size() / WASM_PAGE_SIZE);
                uint32_t grow_pages = a.as_i32();
                if (grow_pages > memory_max_pages - old_pages) {
                    if (!push(Value::i32(UINT32_MAX))) return std::nullopt;
                } else {
                    try {
                        memory.resize(static_cast<size_t>(old_pages + grow_pages) * WASM_PAGE_SIZE);
                        if (!push(Value::i32(old_pages))) return std::nullopt;
                    } catch (const std::bad_alloc&) {
                        if (!push(Value::i32(UINT32_MAX))) return std::nullopt;
                    }
                }
                break;
            }
            case 0x41:
                if (!code.s64(signed_immediate, 5) ||
                    !push(Value::i32(static_cast<uint32_t>(signed_immediate)))) {
                    fail("invalid i32.const");
                    return std::nullopt;
                }
                break;
            case 0x42:
                if (!code.s64(signed_immediate, 10) ||
                    !push(Value::i64(static_cast<uint64_t>(signed_immediate)))) {
                    fail("invalid i64.const");
                    return std::nullopt;
                }
                break;
            case 0x43: {
                std::span<const uint8_t> raw;
                if (!code.bytes(4, raw)) {
                    fail("invalid f32.const");
                    return std::nullopt;
                }
                uint32_t bits = 0;
                std::memcpy(&bits, raw.data(), 4);
                if (!push(Value{ValueType::F32, bits})) return std::nullopt;
                break;
            }
            case 0x44: {
                std::span<const uint8_t> raw;
                if (!code.bytes(8, raw)) {
                    fail("invalid f64.const");
                    return std::nullopt;
                }
                uint64_t bits = 0;
                std::memcpy(&bits, raw.data(), 8);
                if (!push(Value{ValueType::F64, bits})) return std::nullopt;
                break;
            }
            case 0x45: case 0x46: case 0x47: case 0x48: case 0x49:
            case 0x4a: case 0x4b: case 0x4c: case 0x4d: case 0x4e:
            case 0x4f: {
                if (!pop(ValueType::I32, b)) return std::nullopt;
                bool result = false;
                if (opcode == 0x45) {
                    result = b.as_i32() == 0;
                } else {
                    if (!pop(ValueType::I32, a)) return std::nullopt;
                    switch (opcode) {
                        case 0x46: result = a.as_i32() == b.as_i32(); break;
                        case 0x47: result = a.as_i32() != b.as_i32(); break;
                        case 0x48: result = static_cast<int32_t>(a.as_i32()) < static_cast<int32_t>(b.as_i32()); break;
                        case 0x49: result = a.as_i32() < b.as_i32(); break;
                        case 0x4a: result = static_cast<int32_t>(a.as_i32()) > static_cast<int32_t>(b.as_i32()); break;
                        case 0x4b: result = a.as_i32() > b.as_i32(); break;
                        case 0x4c: result = static_cast<int32_t>(a.as_i32()) <= static_cast<int32_t>(b.as_i32()); break;
                        case 0x4d: result = a.as_i32() <= b.as_i32(); break;
                        case 0x4e: result = static_cast<int32_t>(a.as_i32()) >= static_cast<int32_t>(b.as_i32()); break;
                        case 0x4f: result = a.as_i32() >= b.as_i32(); break;
                    }
                }
                if (!push(Value::i32(result ? 1u : 0u))) return std::nullopt;
                break;
            }
            case 0x50: case 0x51: case 0x52: case 0x53: case 0x54:
            case 0x55: case 0x56: case 0x57: case 0x58: case 0x59:
            case 0x5a: {
                if (!pop(ValueType::I64, b)) return std::nullopt;
                bool result = false;
                if (opcode == 0x50) {
                    result = b.as_i64() == 0;
                } else {
                    if (!pop(ValueType::I64, a)) return std::nullopt;
                    switch (opcode) {
                        case 0x51: result = a.as_i64() == b.as_i64(); break;
                        case 0x52: result = a.as_i64() != b.as_i64(); break;
                        case 0x53: result = static_cast<int64_t>(a.as_i64()) < static_cast<int64_t>(b.as_i64()); break;
                        case 0x54: result = a.as_i64() < b.as_i64(); break;
                        case 0x55: result = static_cast<int64_t>(a.as_i64()) > static_cast<int64_t>(b.as_i64()); break;
                        case 0x56: result = a.as_i64() > b.as_i64(); break;
                        case 0x57: result = static_cast<int64_t>(a.as_i64()) <= static_cast<int64_t>(b.as_i64()); break;
                        case 0x58: result = a.as_i64() <= b.as_i64(); break;
                        case 0x59: result = static_cast<int64_t>(a.as_i64()) >= static_cast<int64_t>(b.as_i64()); break;
                        case 0x5a: result = a.as_i64() >= b.as_i64(); break;
                    }
                }
                if (!push(Value::i32(result ? 1u : 0u))) return std::nullopt;
                break;
            }
            case 0x67: case 0x68: case 0x69: {
                if (!pop(ValueType::I32, a)) return std::nullopt;
                uint32_t result = opcode == 0x67 ? std::countl_zero(a.as_i32())
                    : opcode == 0x68 ? std::countr_zero(a.as_i32())
                                     : std::popcount(a.as_i32());
                if (!push(Value::i32(result))) return std::nullopt;
                break;
            }
            case 0x6a: case 0x6b: case 0x6c: case 0x6d: case 0x6e:
            case 0x6f: case 0x70:
            case 0x71: case 0x72: case 0x73: case 0x74: case 0x75:
            case 0x76: case 0x77: case 0x78: {
                if (!pop(ValueType::I32, b) || !pop(ValueType::I32, a)) return std::nullopt;
                uint32_t x = a.as_i32(), y = b.as_i32(), result = 0;
                switch (opcode) {
                    case 0x6a: result = x + y; break;
                    case 0x6b: result = x - y; break;
                    case 0x6c: result = x * y; break;
                    case 0x6d:
                        if (static_cast<int32_t>(y) == 0 ||
                            (x == 0x80000000u && y == UINT32_MAX)) {
                            fail("invalid i32.div_s");
                            return std::nullopt;
                        }
                        result = static_cast<uint32_t>(static_cast<int32_t>(x) / static_cast<int32_t>(y)); break;
                    case 0x6e:
                        if (y == 0) { fail("division by zero"); return std::nullopt; }
                        result = x / y; break;
                    case 0x6f:
                        if (static_cast<int32_t>(y) == 0) {
                            fail("remainder by zero"); return std::nullopt;
                        }
                        result = x == 0x80000000u && y == UINT32_MAX
                            ? 0u : static_cast<uint32_t>(static_cast<int32_t>(x) %
                                                         static_cast<int32_t>(y));
                        break;
                    case 0x70:
                        if (y == 0) { fail("remainder by zero"); return std::nullopt; }
                        result = x % y; break;
                    case 0x71: result = x & y; break;
                    case 0x72: result = x | y; break;
                    case 0x73: result = x ^ y; break;
                    case 0x74: result = x << (y & 31); break;
                    case 0x75: result = static_cast<uint32_t>(static_cast<int32_t>(x) >> (y & 31)); break;
                    case 0x76: result = x >> (y & 31); break;
                    case 0x77: result = std::rotl(x, static_cast<int>(y & 31)); break;
                    case 0x78: result = std::rotr(x, static_cast<int>(y & 31)); break;
                }
                if (!push(Value::i32(result))) return std::nullopt;
                break;
            }
            case 0x79: case 0x7a: case 0x7b: {
                if (!pop(ValueType::I64, a)) return std::nullopt;
                uint64_t value = a.as_i64();
                uint64_t result = opcode == 0x79 ? std::countl_zero(value)
                    : opcode == 0x7a ? std::countr_zero(value)
                                     : std::popcount(value);
                if (!push(Value::i64(result))) return std::nullopt;
                break;
            }
            case 0x7c: case 0x7d: case 0x7e: case 0x7f: case 0x80:
            case 0x81: case 0x82:
            case 0x83: case 0x84: case 0x85: case 0x86: case 0x87:
            case 0x88: case 0x89: case 0x8a: {
                if (!pop(ValueType::I64, b) || !pop(ValueType::I64, a)) return std::nullopt;
                uint64_t x = a.as_i64(), y = b.as_i64(), result = 0;
                switch (opcode) {
                    case 0x7c: result = x + y; break;
                    case 0x7d: result = x - y; break;
                    case 0x7e: result = x * y; break;
                    case 0x7f:
                        if (static_cast<int64_t>(y) == 0 ||
                            (x == (uint64_t{1} << 63) && y == UINT64_MAX)) {
                            fail("invalid i64.div_s"); return std::nullopt;
                        }
                        result = static_cast<uint64_t>(static_cast<int64_t>(x) / static_cast<int64_t>(y)); break;
                    case 0x80:
                        if (y == 0) { fail("division by zero"); return std::nullopt; }
                        result = x / y; break;
                    case 0x81:
                        if (static_cast<int64_t>(y) == 0) {
                            fail("remainder by zero"); return std::nullopt;
                        }
                        result = x == (uint64_t{1} << 63) && y == UINT64_MAX
                            ? 0 : static_cast<uint64_t>(static_cast<int64_t>(x) %
                                                        static_cast<int64_t>(y));
                        break;
                    case 0x82:
                        if (y == 0) { fail("remainder by zero"); return std::nullopt; }
                        result = x % y; break;
                    case 0x83: result = x & y; break;
                    case 0x84: result = x | y; break;
                    case 0x85: result = x ^ y; break;
                    case 0x86: result = x << (y & 63); break;
                    case 0x87: result = static_cast<uint64_t>(static_cast<int64_t>(x) >> (y & 63)); break;
                    case 0x88: result = x >> (y & 63); break;
                    case 0x89: result = std::rotl(x, static_cast<int>(y & 63)); break;
                    case 0x8a: result = std::rotr(x, static_cast<int>(y & 63)); break;
                }
                if (!push(Value::i64(result))) return std::nullopt;
                break;
            }
            case 0xa7:
                if (!pop(ValueType::I64, a) || !push(Value::i32(static_cast<uint32_t>(a.as_i64()))))
                    return std::nullopt;
                break;
            case 0xac:
                if (!pop(ValueType::I32, a) ||
                    !push(Value::i64(static_cast<uint64_t>(static_cast<int64_t>(
                        static_cast<int32_t>(a.as_i32())))))) return std::nullopt;
                break;
            case 0xad:
                if (!pop(ValueType::I32, a) || !push(Value::i64(a.as_i32()))) return std::nullopt;
                break;
            default:
                fail("unsupported opcode 0x" + std::to_string(opcode));
                return std::nullopt;
        }
    }
    fail("function exited without end opcode");
    return std::nullopt;
}

WasmInterpreter::WasmInterpreter(size_t max_memory_bytes,
                                 std::chrono::milliseconds execution_timeout)
    : impl_(std::make_unique<Impl>(max_memory_bytes, execution_timeout)) {}

WasmInterpreter::~WasmInterpreter() = default;

bool WasmInterpreter::load_module(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) {
        impl_->reset();
        impl_->fail("unable to open WebAssembly module: " + path);
        LOG_ERROR("WASM: " + impl_->error);
        return false;
    }
    file.seekg(0, std::ios::end);
    auto file_size = file.tellg();
    if (file_size < 0 || static_cast<uint64_t>(file_size) > MAX_MODULE_SIZE) {
        impl_->reset();
        impl_->fail("WebAssembly module exceeds the 64 MiB input limit");
        LOG_ERROR("WASM: " + impl_->error);
        return false;
    }
    file.seekg(0, std::ios::beg);
    std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(file)),
                               std::istreambuf_iterator<char>());
    if (!impl_->load(bytes)) {
        LOG_ERROR("WASM: failed to load " + path + ": " + impl_->error);
        return false;
    }
    impl_->module_name = path;
    return true;
}

bool WasmInterpreter::load_module_bytes(const uint8_t* data, size_t len) {
    if (data == nullptr && len != 0) {
        impl_->reset();
        impl_->fail("null WebAssembly input");
        return false;
    }
    if (!impl_->load(std::span<const uint8_t>(data, len))) {
        LOG_ERROR("WASM: failed to load module: " + impl_->error);
        return false;
    }
    return true;
}

std::optional<int32_t> WasmInterpreter::call_function(const std::string& name) {
    auto value = impl_->call_export(name);
    if (!value) return std::nullopt;
    if (value->type == ValueType::I32) return static_cast<int32_t>(value->as_i32());
    if (value->type == ValueType::I64) return static_cast<int32_t>(value->as_i64());
    impl_->fail("export result is not an integer");
    return std::nullopt;
}

void WasmInterpreter::set_host_functions(const PluginHostFunctions& funcs) {
    impl_->host = funcs;
}

bool WasmInterpreter::write_memory(uint32_t offset, const void* data, size_t len) {
    if ((!data && len != 0) || !impl_->has_memory || !impl_->range(offset, len)) {
        impl_->fail("write_memory range is invalid");
        return false;
    }
    if (len != 0) std::memcpy(impl_->memory.data() + offset, data, len);
    impl_->error.clear();
    return true;
}

bool WasmInterpreter::read_memory(uint32_t offset, void* data, size_t len) {
    if ((!data && len != 0) || !impl_->has_memory || !impl_->range(offset, len)) {
        impl_->fail("read_memory range is invalid");
        return false;
    }
    if (len != 0) std::memcpy(data, impl_->memory.data() + offset, len);
    impl_->error.clear();
    return true;
}

PluginInfo WasmInterpreter::get_info() const {
    PluginInfo info;
    info.name = impl_->module_name;
    info.version = "wasm-mvp";
    info.description = "JustServer built-in WebAssembly interpreter";
    info.author = "JustServer";
    for (const auto& [name, value] : impl_->exports) {
        if (value.kind != 0) continue;
        if (name == "on_request") info.hooks.push_back(PluginHook::ON_REQUEST);
        else if (name == "on_response") info.hooks.push_back(PluginHook::ON_RESPONSE);
        else if (name == "on_route") info.hooks.push_back(PluginHook::ON_ROUTE);
        else if (name == "on_auth") info.hooks.push_back(PluginHook::ON_AUTH);
        else if (name == "on_log") info.hooks.push_back(PluginHook::ON_LOG);
    }
    return info;
}

std::string WasmInterpreter::last_error() const {
    return impl_->error;
}

} // namespace js
