#pragma once

#include <stdexcept>

namespace jwt {

    /// Polymorphic tag base for every exception this library throws.
    /// `catch (const jwt::Error&)` distinguishes jwt failures from the
    /// standard library's own exceptions and still carries the message via
    /// what(). Each concrete error ALSO derives from the std exception it
    /// historically was, so pre-taxonomy catch sites keep working. Key
    /// material failures (bad seeds, bad public keys) propagate from
    /// nkeys-cpp as nkeys::Error — the layers stay distinguishable.
    class Error {
    public:
        virtual ~Error() = default;
        [[nodiscard]] virtual const char* what() const noexcept = 0;

    protected:
        Error() = default;
        Error(const Error&) = default;
        Error& operator=(const Error&) = default;
    };

    namespace detail {
        template <typename Base>
        class ErrorImpl : public Base, public Error {
        public:
            using Base::Base;
            [[nodiscard]] const char* what() const noexcept override { return Base::what(); }
        };
    } // namespace detail

    /// Not a parseable JWT at all: wrong part count, empty parts, oversized,
    /// bad base64url, payload bytes that aren't JSON.
    class MalformedTokenError : public detail::ErrorImpl<std::invalid_argument> {
        using ErrorImpl::ErrorImpl;
    };

    /// Parses as a JWT, but the claims are wrong or ill-formed: unsupported
    /// header algorithm/version, wrong claim type, bad subject/issuer prefix,
    /// missing required fields, encode by the wrong kind of key, a creds
    /// bundle whose seed doesn't match the JWT subject.
    class InvalidClaimsError : public detail::ErrorImpl<std::invalid_argument> {
        using ErrorImpl::ErrorImpl;
    };

    /// The Ed25519 signature does not verify against the embedded issuer —
    /// tampering, or a token signed by a different key.
    class SignatureError : public detail::ErrorImpl<std::runtime_error> {
        using ErrorImpl::ErrorImpl;
    };

} // namespace jwt
