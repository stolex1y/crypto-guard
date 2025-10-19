#include "crypto_guard_ctx.h"
#include "program_options.h"

#include <fstream>
#include <print>
#include <stdexcept>
#include <string>

int main(int argc, char* argv[]) {
    try {
        crypto_guard::ProgramOptions options;
        const auto parsing_result = options.Parse(std::span(argv, argc));
        if (not parsing_result) {
            std::println("Invalid input options: {}", parsing_result.error());
            return 1;
        }
        if (options.IsHelp()) {
            std::println("{}", options.GetDescription());
            return 0;
        }

        crypto_guard::CryptoGuardCtx crypto_ctx;
        using COMMAND_TYPE = crypto_guard::ProgramOptions::CommandType;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::encrypt: {
            std::ifstream src_file{options.GetInputFile()};
            if (not src_file) {
                std::println("Could not open the input file '{}'", options.GetInputFile().string());
                return 1;
            }
            std::ofstream encrypted_file{options.GetOutputFile()};
            if (not encrypted_file) {
                std::println("Could not open the output file '{}'", options.GetOutputFile().string());
                return 1;
            }
            crypto_ctx.EncryptFile(src_file, encrypted_file, options.GetPassword());
            std::println("File '{}' encrypted successfully to the '{}'", options.GetInputFile().string(),
                         options.GetOutputFile().string());
            break;
        }
        case COMMAND_TYPE::decrypt: {
            std::ifstream encrypted_file{options.GetInputFile()};
            if (not encrypted_file) {
                std::println("Could not open the input file '{}'", options.GetInputFile().string());
                return 1;
            }
            std::ofstream decrypted_file{options.GetOutputFile()};
            if (not decrypted_file) {
                std::println("Could not open the output file '{}'", options.GetOutputFile().string());
                return 1;
            }
            crypto_ctx.DecryptFile(encrypted_file, decrypted_file, options.GetPassword());
            std::println("File '{}' decrypted successfully to the '{}'", options.GetInputFile().string(),
                         options.GetOutputFile().string());
            break;
        }
        case COMMAND_TYPE::checksum: {
            std::ifstream file{options.GetInputFile()};
            if (not file) {
                std::println("Could not open the input file '{}'", options.GetInputFile().string());
                return 1;
            }
            std::println("Checksum: {}", crypto_ctx.CalculateChecksum(file));
            break;
        }
        default: {
            throw std::runtime_error{"Unsupported command"};
        }
        }
    } catch (const std::exception& e) {
        std::println("An error occurred. {}", e.what());
        return 1;
    }

    return 0;
}
