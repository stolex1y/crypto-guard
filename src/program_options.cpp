#include "program_options.h"

#include <expected>
#include <filesystem>
#include <iostream>

namespace po = boost::program_options;

namespace crypto_guard {

[[nodiscard]] std::string MakeOptionName(std::string_view option_name, std::string_view short_name) {
    return std::format("{},{}", option_name, short_name);
}

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    // clang-format off
    desc_.add_options()
        (MakeOptionName(s_option_help, "h").c_str(), po::bool_switch(&help_), "help")
        (MakeOptionName(s_option_command, "c").c_str(), po::value<CommandType>(&command_), "type of command being executed, available values: encrypt, decrypt, checksum")
        (MakeOptionName(s_option_input, "i").c_str(), po::value<std::filesystem::path>(&input_file_), "path to the input file")
        (MakeOptionName(s_option_output, "o").c_str(), po::value<std::filesystem::path>(&output_file_), "path to the file where the result will be saved")
        (MakeOptionName(s_option_password, "p").c_str(), po::value<std::string>(&password_)->default_value(""), "password for encryption and decryption")
    ;
    // clang-format on
}

ProgramOptions::~ProgramOptions() = default;

std::expected<void, std::string> ProgramOptions::Parse(std::span<const char* const> args) const {
    try {
        po::variables_map vm;
        po::store(po::parse_command_line(static_cast<int>(args.size()), args.data(), desc_), vm);
        po::notify(vm);

        if (help_) {
            return {};
        }

        if (not vm.contains(s_option_command)) {
            throw po::required_option(s_option_command);
        }

        if (not vm.contains(s_option_input)) {
            throw po::required_option(s_option_input);
        }

        if (not vm.contains(s_option_output)) {
            throw po::required_option(s_option_output);
        }
    } catch (const po::error& ex) {
        return std::unexpected{ex.what()};
    }

    return {};
}

std::string ProgramOptions::GetDescription() const {
    std::stringstream ss;
    ss << desc_ << std::endl;
    return ss.str();
}

std::optional<ProgramOptions::CommandType> ProgramOptions::ParseCommandType(std::string_view type_str) {
    static const std::unordered_map<std::string_view, CommandType> type_map = {
        {"encrypt", CommandType::encrypt},
        {"decrypt", CommandType::decrypt},
        {"checksum", CommandType::checksum},
    };
    assert(type_map.size() == static_cast<int>(CommandType::LAST));

    const auto it = type_map.find(type_str);
    if (it == type_map.end()) {
        return {};
    }
    return it->second;
}

std::string CommandTypeToString(ProgramOptions::CommandType type) {
    switch (type) {
    case ProgramOptions::CommandType::encrypt:
        return "encrypt";
    case ProgramOptions::CommandType::decrypt:
        return "decrypt";
    case ProgramOptions::CommandType::checksum:
        return "checksum";
    case ProgramOptions::CommandType::LAST:
    default:
        assert(false);
    }
    return std::format("unhandled_{}", static_cast<int>(type));
}

void validate(boost::any& cmd_type, const std::vector<std::string>& values, ProgramOptions::CommandType*, int) {
    po::validators::check_first_occurrence(cmd_type);
    std::string cmd_type_str = po::validators::get_single_string(values);
    std::ranges::transform(cmd_type_str, cmd_type_str.begin(), tolower);
    const auto parsed_cmd_type = ProgramOptions::ParseCommandType(cmd_type_str);
    if (not parsed_cmd_type) {
        throw po::validation_error(po::validation_error::invalid_option_value);
    }
    cmd_type = *parsed_cmd_type;
}

}  // namespace crypto_guard
