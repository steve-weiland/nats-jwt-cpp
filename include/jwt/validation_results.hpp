#pragma once
#include <string>
#include <vector>

namespace jwt {

/// One finding of a validation pass (Go: ValidationIssue). blocking issues
/// are errors; timeCheck issues are expiry/not-before findings, which Go
/// keeps separate so a caller can decide whether "expired" blocks (a server
/// authenticating) or merely informs (a tool inspecting).
struct ValidationIssue {
    std::string description;
    bool blocking = false;
    bool timeCheck = false;
};

/// Accumulated validation report (Go: ValidationResults). Every claim type's
/// `validate(ValidationResults&)` appends ALL of its findings here — nothing
/// stops at the first problem. The throwing `validate()` is built on top of
/// it: it throws the first blocking issue.
class ValidationResults {
public:
    void add(ValidationIssue issue) { issues_.push_back(std::move(issue)); }
    /// Go: AddError — blocking.
    void addError(std::string description) { add({std::move(description), true, false}); }
    /// Go: AddTimeCheck — non-blocking unless the caller says time checks block.
    void addTimeCheck(std::string description) { add({std::move(description), false, true}); }
    /// Go: AddWarning — never blocking.
    void addWarning(std::string description) { add({std::move(description), false, false}); }

    /// Go: IsBlocking(includeTimeChecks).
    [[nodiscard]] bool isBlocking(bool includeTimeChecks) const {
        for (const auto& i : issues_) {
            if (i.blocking) return true;
            if (includeTimeChecks && i.timeCheck) return true;
        }
        return false;
    }
    [[nodiscard]] bool isEmpty() const { return issues_.empty(); }
    /// Go: Errors() — blocking descriptions.
    [[nodiscard]] std::vector<std::string> errors() const {
        std::vector<std::string> out;
        for (const auto& i : issues_) if (i.blocking) out.push_back(i.description);
        return out;
    }
    /// Go: Warnings() — every non-blocking description (time checks included).
    [[nodiscard]] std::vector<std::string> warnings() const {
        std::vector<std::string> out;
        for (const auto& i : issues_) if (!i.blocking) out.push_back(i.description);
        return out;
    }
    [[nodiscard]] const std::vector<ValidationIssue>& issues() const { return issues_; }

private:
    std::vector<ValidationIssue> issues_;
};

}
