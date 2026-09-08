# Contributing to jwt-cpp

Thank you for your interest in contributing to jwt-cpp! This document provides guidelines and best practices for contributing to the project.

## Getting Started

### Prerequisites

- C++20 compatible compiler (GCC 10+, Clang 12+, MSVC 19.29+)
- CMake 3.21 or higher
- Git
- Basic knowledge of JWT and cryptography (helpful but not required)

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/steve-weiland/jwt-cpp.git
cd jwt-cpp

# Build with debug symbols and sanitizers
cmake -S . -B build \
    -DCMAKE_BUILD_TYPE=Debug \
    -DJWT_ENABLE_ASAN=ON \
    -DJWT_WARNINGS_AS_ERRORS=ON

# Build
cmake --build build

# Run tests
ctest --test-dir build --output-on-failure
```

nkeys-cpp will be automatically fetched and built during configuration.

## Building for Development

jwt-cpp automatically handles dependencies via FetchContent. Just clone and build:

```bash
git clone https://github.com/steve-weiland/jwt-cpp.git
cd jwt-cpp
cmake -S . -B build -DCMAKE_BUILD_TYPE=Debug -DJWT_WARNINGS_AS_ERRORS=ON
cmake --build build
ctest --test-dir build
```

No manual dependency installation required! See [CLAUDE.md](CLAUDE.md) for advanced build options.

## How to Contribute

### Reporting Bugs

Before submitting a bug report:
1. Check existing issues to avoid duplicates
2. Verify the bug exists in the latest version
3. Gather relevant information (OS, compiler, CMake version)

**Bug Report Template:**

```markdown
**Description**
Clear description of the bug

**Steps to Reproduce**
1. Step 1
2. Step 2
3. ...

**Expected Behavior**
What should happen

**Actual Behavior**
What actually happens

**Environment**
- OS: [e.g., Ubuntu 22.04, macOS 14.0]
- Compiler: [e.g., GCC 11.3, Clang 15.0]
- CMake: [e.g., 3.25.1]
- Build Type: [Debug/Release]
- nkeys-cpp version: [e.g., 1.0.0]

**Additional Context**
JWT samples, logs, stack traces, etc.
```

### Suggesting Features

Feature requests are welcome! Please include:
- **Use case**: Why is this feature needed?
- **Proposed API**: How should it work?
- **Alternatives**: What other approaches did you consider?
- **Implementation ideas**: How might this be implemented?
- **JWT compatibility**: Does this align with NATS JWT specification?

## Development Guidelines

### Code Style

**Formatting**
- Use 4 spaces for indentation (no tabs)
- Maximum line length: 100 characters
- Opening braces on same line for functions and classes
- Use clang-format (configuration TBD)

**Naming Conventions**
```cpp
// Classes: PascalCase
class OperatorClaims { ... };

// Functions: camelCase
void encodePayload(...);

// Variables: camelCase
std::string jwtToken;

// Constants: UPPER_SNAKE_CASE
inline constexpr int JWT_VERSION = 2;

// Namespaces: lowercase
namespace jwt { ... }
```

**Modern C++ Practices**
```cpp
// ✅ Prefer auto with clear types
auto claims = jwt::OperatorClaims(operatorKey);

// ✅ Use std::span for non-owning views
void processPayload(std::span<const uint8_t> data);

// ✅ Use [[nodiscard]] for pure functions
[[nodiscard]] virtual std::string encode(...) const = 0;

// ✅ Use std::unique_ptr for ownership
std::unique_ptr<Claims> decode(const std::string& jwt);

// ✅ Use std::optional for nullable values
[[nodiscard]] virtual std::optional<std::string> name() const = 0;

// ❌ Don't use raw pointers for ownership
Claims* decode(const std::string& jwt); // No!

// ❌ Don't use C-style casts
int x = (int)value; // No!
int x = static_cast<int>(value); // Yes!
```

### Error Handling

**Exception Policy**
- Throw only the typed errors from `jwt_errors.hpp` — pick the category:
  `MalformedTokenError` (not a parseable JWT), `InvalidClaimsError` (parses
  but wrong: header/type/version/prefixes/fields), `SignatureError`
  (authentication failed). Never a bare std exception — callers rely on
  `catch (jwt::Error)` seeing everything this library throws. Key-material
  failures propagate from nkeys-cpp as `nkeys::Error`.
- Never throw from destructors or `noexcept` functions

**Error Message Format**
```cpp
// ✅ Good: Descriptive with component and reason
throw MalformedTokenError("Invalid JWT: missing signature component");

// ❌ Bad: Vague or abbreviated
throw MalformedTokenError("bad jwt");
```

### Memory Safety

**Critical Rules**
1. Always wipe sensitive data when done (seeds, private keys)
2. Use RAII for automatic cleanup
3. Use `volatile` for security-critical zeroing
4. Test with AddressSanitizer
5. Rely on nkeys-cpp for cryptographic operations (don't implement crypto)

**Example: Handling Seeds Securely**
```cpp
// ✅ Good: Let nkeys-cpp handle sensitive data
std::string jwt = claims.encode(seed); // nkeys-cpp handles seed securely

// ❌ Bad: Exposing seed unnecessarily
std::string seedCopy = seed; // Unnecessary copy of sensitive data
```

### Testing Requirements

All contributions must include tests:

**What to Test**
- ✅ All new public APIs
- ✅ Error conditions and exceptions (malformed JWT, invalid signatures)
- ✅ Edge cases (expired tokens, missing fields, empty values)
- ✅ Security properties (signature verification, claim validation)
- ✅ JWT compatibility (ensure compatibility with NATS JWT Go library)

**Test Structure**
```cpp
TEST(JwtTest, DescriptiveName) {
    // Arrange: Set up test data
    auto claims = jwt::OperatorClaims("OABC...");
    claims.setName("TestOperator");

    // Act: Perform operation
    std::string token = claims.encode(operatorSeed);

    // Assert: Verify results
    auto decoded = jwt::decodeOperatorClaims(token);
    EXPECT_EQ(decoded->name(), "TestOperator");
}
```

**Running Tests**
```bash
# Standard test run
ctest --test-dir build --output-on-failure

# With sanitizers
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DJWT_ENABLE_ASAN=ON -DCMAKE_PREFIX_PATH=~/local
cmake --build build
ctest --test-dir build

# Verbose output
ctest --test-dir build --verbose
```

### Documentation

**Code Documentation**
- Add comments for non-obvious logic
- Document all public APIs with Doxygen-style comments
- Include parameter descriptions and return values
- Note any exceptions that can be thrown
- Reference NATS JWT spec when relevant

**Example:**
```cpp
/// Encodes the claims into a signed JWT string.
/// @param seed Ed25519 seed for signing (from nkeys-cpp)
/// @return JWT string in format: header.payload.signature (Base64 URL encoded)
/// @throws std::invalid_argument if claims are invalid
/// @throws std::runtime_error if signing fails
[[nodiscard]] std::string encode(const std::string& seed) const;
```

**User Documentation**
- Update README.md for new features
- Add examples for new APIs
- Update CLAUDE.md for Claude Code initialization
- Update SECURITY.md for security-relevant changes

## Pull Request Process

### Before Submitting

**Checklist:**
- [ ] Code follows style guidelines
- [ ] All tests pass locally
- [ ] New tests added for new features
- [ ] Documentation updated
- [ ] Commit messages are clear and descriptive
- [ ] No compiler warnings
- [ ] Sanitizers pass (ASAN, UBSAN)
- [ ] JWT tokens are compatible with NATS spec

### Commit Messages

Follow conventional commits format:

```
<type>: <description>

[optional body]

[optional footer]
```

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `test`: Test additions or changes
- `refactor`: Code restructuring without behavior change
- `perf`: Performance improvements
- `build`: Build system changes
- `ci`: CI/CD changes

**Examples:**
```
feat: implement operator claims encoding

Implements OperatorClaims::encode() with Base64 URL encoding
and Ed25519 signature generation via nkeys-cpp.
Includes comprehensive tests for encoding/decoding.

Closes #123
```

```
fix: correct Base64 URL padding removal

Base64 URL encoding was not properly removing trailing '='
characters, causing JWT parsing failures in some clients.
```

### Pull Request Template

```markdown
## Description
Brief description of changes

## Motivation
Why is this change needed?

## Changes
- Bullet list of changes

## Testing
How was this tested?

## JWT Compatibility
- [ ] Tested with NATS JWT Go library (if applicable)
- [ ] Follows NATS JWT v2 specification

## Checklist
- [ ] Tests pass
- [ ] Documentation updated
- [ ] Sanitizers pass
- [ ] No new warnings
```

### Review Process

1. **Automated Checks**: CI must pass
2. **Code Review**: At least one maintainer approval
3. **Discussion**: Address all review comments
4. **Merge**: Squash or merge based on maintainer preference

## Code of Conduct

### Our Standards

- **Respectful**: Treat everyone with respect
- **Collaborative**: Work together towards common goals
- **Constructive**: Provide helpful feedback
- **Professional**: Maintain professional conduct

### Unacceptable Behavior

- Harassment, discrimination, or offensive language
- Personal attacks or trolling
- Publishing private information
- Unprofessional or unwelcome conduct

## Development Workflow

### Branch Strategy

- `main`: Stable, release-ready code
- `develop`: Integration branch for features
- `feature/*`: Feature branches
- `fix/*`: Bug fix branches

### Typical Workflow

```bash
# Create feature branch
git checkout -b feature/my-feature

# Make changes, test locally
# ...

# Commit changes
git add .
git commit -m "feat: add my feature"

# Push and create PR
git push origin feature/my-feature
```

## Security-Sensitive Changes

For changes involving JWT security or cryptography:

1. **Extra scrutiny**: Security-critical code requires thorough review
2. **Testing**: Include security-focused tests (signature verification, expiration checks)
3. **Documentation**: Update SECURITY.md if threat model changes
4. **Expert review**: Consider external security review for major changes

**Never:**
- Implement custom cryptographic algorithms (use nkeys-cpp)
- Disable signature verification without justification
- Skip validation of JWT claims
- Introduce timing vulnerabilities in signature checks
- Accept JWTs with expired timestamps without explicit opt-in

**JWT-Specific Security Considerations:**
- Always verify signatures before trusting claims
- Validate expiration timestamps (`exp` field)
- Check issuer/subject relationships (account signed by operator, user signed by account)
- Reject JWTs with missing required fields
- Use constant-time comparisons for signature verification (handled by nkeys-cpp)

## Getting Help

- **Questions**: Open a GitHub discussion
- **Chat**: [Link to Discord/Slack if available]
- **Email**: [Maintainer email]

## Recognition

Contributors are recognized in:
- Git commit history
- Release notes
- Contributors list (if we add one)

## Additional Resources

- **NATS JWT Specification**: https://github.com/nats-io/jwt
- **nkeys-cpp Documentation**: https://github.com/steve-weiland/nkeys-cpp
- **JWT RFC**: https://datatracker.ietf.org/doc/html/rfc7519
- **Base64 URL Encoding**: https://datatracker.ietf.org/doc/html/rfc4648#section-5

Thank you for contributing to jwt-cpp! Your efforts help make secure NATS authentication accessible to everyone.
