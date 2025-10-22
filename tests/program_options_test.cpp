#include "program_options.h"

#include <gtest/gtest.h>

using namespace std::string_literals;

namespace crypto_guard::test {

class ProgramOptionsTest : public testing::Test {
public:
    using CliArg = const char*;

    [[nodiscard]] std::vector<CliArg> TestOptionsToCli() const {
        std::vector<CliArg> options;
        options.emplace_back("CryptoGuard");
        for (const auto& [key, value] : test_options_) {
            options.emplace_back(key.c_str());
            if (!value.empty()) {
                options.emplace_back(value.c_str());
            }
        }
        return options;
    }

    [[nodiscard]] std::expected<ProgramOptions, std::string> ParseTestOptions() const {
        const auto options = TestOptionsToCli();
        return ProgramOptions::Parse(std::span(options.data(), options.size()));
    }

    std::unordered_map<std::string, std::string> test_options_;
};

TEST_F(ProgramOptionsTest, help_by_short_name_without_other_options) {
    test_options_["-h"];
    const auto res = ParseTestOptions();
    ASSERT_TRUE(res.has_value());
    const auto& po = res.value();
    ASSERT_TRUE(po.IsHelp());
    ASSERT_TRUE(po.GetDescription().find("Allowed options") != std::string_view::npos);
}

TEST_F(ProgramOptionsTest, help_by_short_name_with_other_options) {
    test_options_["-h"];
    test_options_["-i"] = "input.txt";
    test_options_["-o"] = "output.txt";
    test_options_["-p"] = "pass";
    const auto res = ParseTestOptions();
    ASSERT_TRUE(res.has_value());
    const auto& po = res.value();
    ASSERT_TRUE(po.IsHelp());
    ASSERT_TRUE(po.GetDescription().find("Allowed options") != std::string_view::npos);
}

TEST_F(ProgramOptionsTest, help_without_other_options) {
    test_options_["--help"];
    const auto res = ParseTestOptions();
    ASSERT_TRUE(res.has_value());
    const auto& po = res.value();
    ASSERT_TRUE(po.IsHelp());
    ASSERT_TRUE(po.GetDescription().find("Allowed options") != std::string_view::npos);
}

TEST_F(ProgramOptionsTest, help_with_other_options) {
    test_options_["--help"];
    test_options_["-i"] = "input.txt";
    test_options_["-o"] = "output.txt";
    test_options_["-p"] = "pass";
    const auto res = ParseTestOptions();
    ASSERT_TRUE(res.has_value());
    const auto& po = res.value();
    ASSERT_TRUE(po.IsHelp());
    ASSERT_TRUE(po.GetDescription().find("Allowed options") != std::string_view::npos);
}

TEST_F(ProgramOptionsTest, empty_options) {
    const auto res = ParseTestOptions();
    ASSERT_FALSE(res.has_value());
    ASSERT_TRUE(res.error().find("is required but missing") != std::string_view::npos);
}

TEST_F(ProgramOptionsTest, unrecognised_option) {
    test_options_["--hekp"];
    const auto res = ParseTestOptions();
    ASSERT_FALSE(res.has_value());
    ASSERT_TRUE(res.error().find("unrecognised option") != std::string_view::npos);
}

TEST_F(ProgramOptionsTest, unknown_command_option) {
    test_options_["--command"] = "enxrypt";
    const auto res = ParseTestOptions();
    ASSERT_FALSE(res.has_value());
    ASSERT_TRUE(res.error().find("'--command' is invalid") != std::string_view::npos);
}

TEST_F(ProgramOptionsTest, encrypt_command_with_all_options) {
    constexpr auto option_input = "input.txt";
    constexpr auto option_output = "output";
    constexpr auto option_password = "pass";
    test_options_["--command"] = "encrypt";
    test_options_["--input"] = option_input;
    test_options_["--output"] = option_output;
    test_options_["--password"] = option_password;
    const auto res = ParseTestOptions();
    ASSERT_TRUE(res.has_value());
    const auto& po = res.value();
    ASSERT_EQ(po.GetCommand(), ProgramOptions::CommandType::encrypt);
    ASSERT_EQ(po.GetInputFile(), option_input);
    ASSERT_EQ(po.GetOutputFile(), option_output);
    ASSERT_EQ(po.GetPassword(), option_password);
    ASSERT_FALSE(po.IsHelp());
}

TEST_F(ProgramOptionsTest, decrypt_command_with_all_options) {
    constexpr auto option_input = "input.txt";
    constexpr auto option_output = "output";
    constexpr auto option_password = "pass";
    test_options_["--command"] = "decrypt";
    test_options_["--input"] = option_input;
    test_options_["--output"] = option_output;
    test_options_["--password"] = option_password;
    const auto res = ParseTestOptions();
    ASSERT_TRUE(res.has_value());
    const auto& po = res.value();
    ASSERT_EQ(po.GetCommand(), ProgramOptions::CommandType::decrypt);
    ASSERT_EQ(po.GetInputFile(), option_input);
    ASSERT_EQ(po.GetOutputFile(), option_output);
    ASSERT_EQ(po.GetPassword(), option_password);
    ASSERT_FALSE(po.IsHelp());
}

TEST_F(ProgramOptionsTest, checksum_command_with_all_options) {
    constexpr auto option_input = "input.txt";
    test_options_["--command"] = "checksum";
    test_options_["--input"] = option_input;
    const auto res = ParseTestOptions();
    ASSERT_TRUE(res.has_value());
    const auto& po = res.value();
    ASSERT_EQ(po.GetCommand(), ProgramOptions::CommandType::checksum);
    ASSERT_EQ(po.GetInputFile(), option_input);
    ASSERT_FALSE(po.IsHelp());
}

}  // namespace crypto_guard::test
