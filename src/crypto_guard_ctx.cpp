#include "crypto_guard_ctx.h"

#include <openssl/err.h>
#include <openssl/evp.h>

#include <array>
#include <iomanip>
#include <sstream>

namespace crypto_guard {

struct AesCipherParams {
    static constexpr size_t KEY_SIZE = 32;  // AES-256 key size
    static constexpr size_t IV_SIZE = 16;   // AES block size (IV length)

    const EVP_CIPHER* cipher{EVP_aes_256_cbc()};  // Cipher algorithm

    int encrypt{};                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, KEY_SIZE> key{};  // Encryption key
    std::array<unsigned char, IV_SIZE> iv{};    // Initialization vector
};

class CryptoGuardCtx::Impl {
public:
    void EncryptFile(std::istream& in_stream, std::ostream& out_stream, std::string_view password) {
        ProcessFile(in_stream, out_stream, password, true);
    }

    void DecryptFile(std::istream& in_stream, std::ostream& out_stream, std::string_view password) {
        ProcessFile(in_stream, out_stream, password, false);
    }

    [[nodiscard]] std::string CalculateChecksum(std::istream& in_stream) {
        if (in_stream.fail() and not in_stream.eof()) {
            throw std::runtime_error("Invalid input stream");
        }

        const auto ctx = CreateMdCtx();
        while (not in_stream.eof()) {
            in_stream.read(in_buf_.data(), in_buf_.size());
            if (in_stream.fail() and not in_stream.eof()) {
                throw std::runtime_error("Couldn't read from input stream");
            }
            const auto bytes_read = in_stream.gcount();

            if (not EVP_DigestUpdate(ctx.get(), in_buf_.data(), bytes_read)) {
                throw std::runtime_error(std::format("Couldn't calculate checksum: {}", GetErrReason()));
            }
        }

        uint32_t out_len{};
        if (not EVP_DigestFinal_ex(ctx.get(), reinterpret_cast<unsigned char*>(out_buf_.data()), &out_len)) {
            throw std::runtime_error(std::format("Couldn't calculate checksum: {}", GetErrReason()));
        }

        std::stringstream digest_stream;
        digest_stream << std::hex << std::setfill('0');
        for (size_t i = 0; i < out_len; ++i) {
            const int byte = static_cast<uint8_t>(out_buf_[i]);
            digest_stream << std::setw(2) << byte;
        }
        return digest_stream.str();
    }

private:
    struct EvpCipherCtxDeleter {
        void operator()(EVP_CIPHER_CTX* ctx) const { EVP_CIPHER_CTX_free(ctx); }
    };

    struct EvpMdCtxDeleter {
        void operator()(EVP_MD_CTX* ctx) const { EVP_MD_CTX_free(ctx); }
    };

    using EvpCipherCtxPtr = std::unique_ptr<EVP_CIPHER_CTX, EvpCipherCtxDeleter>;
    using EvpMdCtxPtr = std::unique_ptr<EVP_MD_CTX, EvpMdCtxDeleter>;

    static constexpr std::string_view kSalt{"12345678"};
    static constexpr size_t kBufSize{16 * 1024};  // 16 KiB

    static AesCipherParams CreateCipherParamsFromPassword(std::string_view password) {
        AesCipherParams params{};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), reinterpret_cast<const unsigned char*>(kSalt.data()),
                                    reinterpret_cast<const unsigned char*>(password.data()),
                                    static_cast<int>(password.size()), 1, params.key.data(), params.iv.data());

        if (not result) {
            throw std::runtime_error{std::format("Failed to create a key from password: {}", GetErrReason())};
        }

        return params;
    }

    static EvpCipherCtxPtr CreateCipherCtx(std::string_view password, bool encrypt) {
        auto ctx = EvpCipherCtxPtr{EVP_CIPHER_CTX_new()};
        if (not ctx) {
            throw std::runtime_error(std::format("Couldn't create cipher context: {}", GetErrReason()));
        }

        auto params = CreateCipherParamsFromPassword(password);
        params.encrypt = encrypt ? 1 : 0;

        if (not EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(),
                                  params.encrypt)) {
            throw std::runtime_error(std::format("Couldn't initialize cipher context: {}", GetErrReason()));
        }

        return ctx;
    }

    static std::string GetErrReason() {
        const auto ec = ERR_get_error();
        if (not ec) {
            return {};
        }
        return ERR_reason_error_string(ec);
    }

    static EvpMdCtxPtr CreateMdCtx() {
        auto ctx = EvpMdCtxPtr{EVP_MD_CTX_new()};
        if (not ctx) {
            throw std::runtime_error(std::format("Couldn't create md context: {}", GetErrReason()));
        }
        const auto md = EVP_sha256();
        if (not EVP_DigestInit_ex2(ctx.get(), md, nullptr)) {
            throw std::runtime_error(std::format("Couldn't initialize md context: {}", GetErrReason()));
        }
        return ctx;
    }

    void ProcessFile(std::istream& in_stream, std::ostream& out_stream, std::string_view password, bool encrypt) {
        if (in_stream.fail() and not in_stream.eof()) {
            throw std::runtime_error{"Invalid input stream"};
        }
        if (not out_stream) {
            throw std::runtime_error{"Invalid output stream"};
        }

        const auto ctx = CreateCipherCtx(password, encrypt);

        while (not in_stream.eof()) {
            in_stream.read(in_buf_.data(), in_buf_.size());
            if (in_stream.fail() and not in_stream.eof()) {
                throw std::runtime_error("Couldn't read from input stream");
            }
            const auto bytes_read = in_stream.gcount();

            int out_len{};
            if (not EVP_CipherUpdate(ctx.get(), reinterpret_cast<unsigned char*>(out_buf_.data()), &out_len,
                                     reinterpret_cast<const unsigned char*>(in_buf_.data()), bytes_read)) {
                throw std::runtime_error(
                    std::format("Couldn't {} data: {}", encrypt ? "encrypt" : "decrypt", GetErrReason()));
            }
            out_stream.write(out_buf_.data(), out_len);
            if (not out_stream) {
                throw std::runtime_error("Couldn't write to output stream");
            }
        }

        int out_len{};
        if (not EVP_CipherFinal_ex(ctx.get(), reinterpret_cast<unsigned char*>(out_buf_.data()), &out_len)) {
            throw std::runtime_error(
                std::format("Couldn't {} data: {}", encrypt ? "encrypt" : "decrypt", GetErrReason()));
        }
        out_stream.write(out_buf_.data(), out_len);
        if (not out_stream) {
            throw std::runtime_error("Couldn't write to output stream");
        }
    }

    std::array<char, kBufSize> in_buf_{};
    std::array<char, kBufSize + EVP_MAX_BLOCK_LENGTH> out_buf_{};
};

CryptoGuardCtx::CryptoGuardCtx() : impl_{std::make_unique<Impl>()} {}

CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::istream& in_stream, std::ostream& out_stream, std::string_view password) {
    impl_->EncryptFile(in_stream, out_stream, password);
}

void CryptoGuardCtx::DecryptFile(std::istream& in_stream, std::ostream& out_stream, std::string_view password) {
    impl_->DecryptFile(in_stream, out_stream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::istream& in_stream) { return impl_->CalculateChecksum(in_stream); }

}  // namespace crypto_guard
