#include "crypto_guard_ctx.h"

#include <fstream>

#include <gtest/gtest.h>

namespace crypto_guard::test {

class CryptoGuardCtxTest : public ::testing::Test {
public:
    static std::stringstream GenerateRandomFileContent(size_t len) {
        std::stringstream ss;
        for (size_t i = 0; i < len; i++) {
            ss << static_cast<char>(lrand48() % 256);
        }
        return ss;
    }

    CryptoGuardCtx ctx_;
};

TEST_F(CryptoGuardCtxTest, encrypt_decrypt_file_with_pass) {
    constexpr auto pass = "pass";
    std::stringstream file_content{GenerateRandomFileContent(1025 * 1023 * 3)};
    std::stringstream encrypted_file_content;
    ctx_.EncryptFile(file_content, encrypted_file_content, pass);
    ASSERT_NE(encrypted_file_content.view(), file_content.view());
    std::stringstream decrypted_file_content;
    ctx_.DecryptFile(encrypted_file_content, decrypted_file_content, pass);
    ASSERT_EQ(decrypted_file_content.view(), file_content.view());
}

TEST_F(CryptoGuardCtxTest, encrypt_decrypt_empty_file) {
    constexpr auto pass = "pass";
    std::stringstream file_content;
    std::stringstream encrypted_file_content;
    ctx_.EncryptFile(file_content, encrypted_file_content, pass);
    ASSERT_NE(encrypted_file_content.view(), file_content.view());
    std::stringstream decrypted_file_content;
    ctx_.DecryptFile(encrypted_file_content, decrypted_file_content, pass);
    ASSERT_TRUE(decrypted_file_content.view().empty());
}

TEST_F(CryptoGuardCtxTest, encrypt_decrypt_file_without_pass) {
    constexpr auto empty_pass = "";
    std::stringstream file_content{GenerateRandomFileContent(1025 * 1023 * 3)};
    std::stringstream encrypted_file_content;
    ctx_.EncryptFile(file_content, encrypted_file_content, empty_pass);
    ASSERT_NE(encrypted_file_content.view(), file_content.view());
    std::stringstream decrypted_file_content;
    ctx_.DecryptFile(encrypted_file_content, decrypted_file_content, empty_pass);
    ASSERT_EQ(decrypted_file_content.view(), file_content.view());
}

TEST_F(CryptoGuardCtxTest, encrypt_decrypt_file_with_different_passwords) {
    constexpr auto encrypt_pass = "pass1";
    constexpr auto decrypt_pass = "pass2";
    std::stringstream file_content{GenerateRandomFileContent(1025 * 1023 * 3)};
    std::stringstream encrypted_file_content;
    ctx_.EncryptFile(file_content, encrypted_file_content, encrypt_pass);
    ASSERT_NE(encrypted_file_content.view(), file_content.view());
    std::stringstream decrypted_file_content;
    ASSERT_THROW(ctx_.DecryptFile(encrypted_file_content, decrypted_file_content, decrypt_pass), std::runtime_error);
}

TEST_F(CryptoGuardCtxTest, try_to_encrypt_invalid_input_file) {
    constexpr auto pass = "pass";
    std::ifstream input_file{GenerateRandomFileContent(10).str()};
    std::stringstream encrypted_file;
    ASSERT_THROW(ctx_.EncryptFile(input_file, encrypted_file, pass), std::runtime_error);
}

TEST_F(CryptoGuardCtxTest, try_to_encrypt_invalid_output_file) {
    constexpr auto pass = "pass";
    std::stringstream file_content{"test"};
    std::ofstream output_file{GenerateRandomFileContent(10).str(), std::ios_base::in};
    ASSERT_THROW(ctx_.EncryptFile(file_content, output_file, pass), std::runtime_error);
}

TEST_F(CryptoGuardCtxTest, try_to_decrypt_invalid_input_file) {
    constexpr auto pass = "pass";
    std::ifstream input_file{GenerateRandomFileContent(10).str()};
    std::stringstream decrypted_file;
    ASSERT_THROW(ctx_.DecryptFile(input_file, decrypted_file, pass), std::runtime_error);
}

TEST_F(CryptoGuardCtxTest, try_to_decrypt_invalid_output_file) {
    constexpr auto pass = "pass";
    std::stringstream file_content{"test"};
    std::ofstream output_file{GenerateRandomFileContent(10).str(), std::ios_base::in};
    ASSERT_THROW(ctx_.DecryptFile(file_content, output_file, pass), std::runtime_error);
}

TEST_F(CryptoGuardCtxTest, calculate_checksum) {
    std::stringstream file_content;
    file_content << "Test string";
    constexpr auto expected_checksum = "a3e49d843df13c2e2a7786f6ecd7e0d184f45d718d1ac1a8a63e570466e489dd";
    const auto actual_checksum = ctx_.CalculateChecksum(file_content);
    ASSERT_EQ(actual_checksum, expected_checksum);
}

TEST_F(CryptoGuardCtxTest, try_to_calculate_checksum_with_invalid_input_file) {
    std::ifstream input_file{GenerateRandomFileContent(10).str()};
    ASSERT_THROW(ctx_.CalculateChecksum(input_file), std::runtime_error);
}

TEST_F(CryptoGuardCtxTest, calculate_checksum_with_empty_file) {
    std::stringstream file_content;
    constexpr auto expected_checksum = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    const auto actual_checksum = ctx_.CalculateChecksum(file_content);
    ASSERT_EQ(actual_checksum, expected_checksum);
}

TEST_F(CryptoGuardCtxTest, calculate_checksum_after_encryption_and_decryption) {
    constexpr auto pass = "pass";
    std::stringstream file_content{GenerateRandomFileContent(1025 * 1023 * 3)};
    const auto checksum_before = ctx_.CalculateChecksum(file_content);
    file_content.clear();
    file_content.seekg(0, std::ios::beg);

    std::stringstream encrypted_file_content;
    ctx_.EncryptFile(file_content, encrypted_file_content, pass);
    ASSERT_NE(encrypted_file_content.view(), file_content.view());
    std::stringstream decrypted_file_content;
    ctx_.DecryptFile(encrypted_file_content, decrypted_file_content, pass);
    ASSERT_EQ(decrypted_file_content.view(), file_content.view());

    const auto checksum_after = ctx_.CalculateChecksum(decrypted_file_content);
    ASSERT_EQ(checksum_after, checksum_before);
}

}  // namespace crypto_guard::test
