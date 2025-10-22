#pragma once

#include <experimental/propagate_const>
#include <iostream>
#include <memory>
#include <string>

namespace crypto_guard {

class CryptoGuardCtx {
public:
    CryptoGuardCtx();
    ~CryptoGuardCtx();

    CryptoGuardCtx(const CryptoGuardCtx&) = delete;
    CryptoGuardCtx& operator=(const CryptoGuardCtx&) = delete;

    CryptoGuardCtx(CryptoGuardCtx&&) noexcept = default;
    CryptoGuardCtx& operator=(CryptoGuardCtx&&) noexcept = default;

    void EncryptFile(std::istream& in_stream, std::ostream& out_stream, std::string_view password);
    void DecryptFile(std::istream& in_stream, std::ostream& out_stream, std::string_view password);
    std::string CalculateChecksum(std::istream& in_stream);

private:
    class Impl;

    std::experimental::propagate_const<std::unique_ptr<Impl>> impl_;
};

}  // namespace crypto_guard
