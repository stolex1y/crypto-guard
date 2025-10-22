#pragma once

#include <expected>
#include <filesystem>
#include <string>

#include <boost/program_options.hpp>

namespace crypto_guard {

class ProgramOptions {
public:
    enum class CommandType { encrypt, decrypt, checksum, LAST };

    [[nodiscard]] static std::optional<CommandType> ParseCommandType(std::string_view type_str);
    [[nodiscard]] static std::expected<ProgramOptions, std::string> Parse(std::span<const char* const> args);

    ~ProgramOptions();

    [[nodiscard]] CommandType GetCommand() const { return command_; }
    [[nodiscard]] std::filesystem::path GetInputFile() const { return input_file_; }
    [[nodiscard]] std::filesystem::path GetOutputFile() const { return output_file_; }
    [[nodiscard]] std::string GetPassword() const { return password_; }
    [[nodiscard]] bool IsHelp() const { return help_; }
    [[nodiscard]] std::string GetDescription() const;

private:
    static constexpr auto kOptionCommand = "command";
    static constexpr auto kOptionInput = "input";
    static constexpr auto kOptionOutput = "output";
    static constexpr auto kOptionPassword = "password";
    static constexpr auto kOptionHelp = "help";

    ProgramOptions();

    CommandType command_{};
    std::filesystem::path input_file_;
    std::filesystem::path output_file_;
    std::string password_;
    bool help_;

    boost::program_options::options_description desc_;
};

[[nodiscard]] std::string CommandTypeToString(ProgramOptions::CommandType type);

void validate(boost::any& cmd_type, const std::vector<std::string>& values, ProgramOptions::CommandType*, int);

}  // namespace crypto_guard
