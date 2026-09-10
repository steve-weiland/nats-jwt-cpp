#pragma once
// Internal: Go's Subject / RenamingSubject / Info / Permission rules
// (types.go), texts verbatim — shared by accounts (exports, imports, default
// permissions, mappings) and users (permissions).
#include "jwt/permissions.hpp"
#include "jwt/validation_results.hpp"
#include <string>
#include <vector>

namespace jwt::internal {

inline std::vector<std::string> splitOn(const std::string& s, char sep) {
    std::vector<std::string> out;
    std::size_t pos = 0;
    while (true) {
        auto next = s.find(sep, pos);
        if (next == std::string::npos) { out.push_back(s.substr(pos)); break; }
        out.push_back(s.substr(pos, next - pos));
        pos = next + 1;
    }
    return out;
}

// Go: Subject.Validate
inline void validateSubject(const std::string& v, ValidationResults& vr) {
    if (v.empty()) {
        vr.addError("subject cannot be empty");
        return;  // Go: "No other checks after that make sense"
    }
    if (v.find(' ') != std::string::npos) vr.addError("subject \"" + v + "\" cannot have spaces");
    if (v.front() == '.' || v.back() == '.') vr.addError("subject \"" + v + "\" cannot start or end with a `.`");
    if (v.find("..") != std::string::npos) vr.addError("subject \"" + v + "\" cannot contain consecutive `.`");
}

// Go: Subject.HasWildCards
inline bool subjectHasWildcards(const std::string& v) {
    auto endsWith = [&](const char* suf) {
        const std::string s(suf);
        return v.size() >= s.size() && v.compare(v.size() - s.size(), s.size(), s) == 0;
    };
    return endsWith(".>") || v.find(".*.") != std::string::npos || endsWith(".*") ||
           v.rfind("*.", 0) == 0 || v == "*" || v == ">";
}

// Go: Subject.countTokenWildcards
inline int countTokenWildcards(const std::string& v) {
    if (v == "*") return 1;
    int cnt = 0;
    for (const auto& t : splitOn(v, '.')) if (t == "*") ++cnt;
    return cnt;
}

// Go: Subject.IsContainedIn
inline bool subjectIsContainedIn(const std::string& s, const std::string& other) {
    const auto otherArr = splitOn(other, '.');
    const auto myArr = splitOn(s, '.');
    if (myArr.size() > otherArr.size() && otherArr.back() != ">") return false;
    if (myArr.size() < otherArr.size()) return false;
    for (std::size_t i = 0; i < otherArr.size(); ++i) {
        const auto& tok = otherArr[i];
        if (i == otherArr.size() - 1 && tok == ">") return true;
        if (tok != myArr[i] && tok != "*") return false;
    }
    return true;
}

inline bool isDigits(const std::string& s) {
    return !s.empty() && s.find_first_not_of("0123456789") == std::string::npos;
}

// Go: RenamingSubject.Validate(from)
inline void validateRenamingSubject(const std::string& s, const std::string& from, ValidationResults& vr) {
    validateSubject(s, vr);
    if (from.empty()) vr.addError("subject cannot be empty");
    if (s.find(' ') != std::string::npos) vr.addError("subject \"" + s + "\" cannot have spaces");
    auto matchesSuffix = [](const std::string& x) {
        return x == ">" || (x.size() >= 2 && x.compare(x.size() - 2, 2, ".>") == 0);
    };
    if (matchesSuffix(s) != matchesSuffix(from)) {
        vr.addError("both, renaming subject and subject, need to end or not end in >");
    }
    const int fromCnt = countTokenWildcards(from);
    int refCnt = 0;
    for (const auto& tk : splitOn(s, '.')) {
        if (tk == "*") ++refCnt;
        if (tk.size() < 2) continue;
        if (tk[0] == '$' && isDigits(tk.substr(1))) {
            const int idx = std::stoi(tk.substr(1));
            if (idx > fromCnt) {
                vr.addError("Reference $" + std::to_string(idx) + " in \"" + s + "\" reference * in \"" + from +
                            "\" that do not exist");
            } else {
                ++refCnt;
            }
        }
    }
    if (refCnt != fromCnt) vr.addError("subject does not contain enough * or reference wildcards $[0-9]");
}

// Go: RenamingSubject.ToSubject — $N references become *
inline std::string renamingToSubject(const std::string& s) {
    if (s.find('$') == std::string::npos) return s;
    std::string out;
    const auto tokens = splitOn(s, '.');
    for (std::size_t i = 0; i < tokens.size(); ++i) {
        const auto& tk = tokens[i];
        const bool convert = tk.size() > 1 && tk[0] == '$' && isDigits(tk.substr(1));
        if (i) out += '.';
        out += convert ? "*" : tk;
    }
    return out;
}

// Go: Info.Validate — url.Parse must succeed with a scheme AND a hostname
inline void validateInfo(const std::string& description, const std::string& infoURL, ValidationResults& vr) {
    constexpr std::size_t MaxInfoLength = 8 * 1024;
    if (description.size() > MaxInfoLength) vr.addError("Description is too long");
    if (infoURL.empty()) return;
    if (infoURL.size() > MaxInfoLength) vr.addError("Info URL is too long");
    bool ok = false;
    const auto sep = infoURL.find("://");
    if (sep != std::string::npos && sep > 0) {
        std::string rest = infoURL.substr(sep + 3);
        auto end = rest.find_first_of("/?#");
        std::string authority = rest.substr(0, end);
        auto at = authority.rfind('@');
        if (at != std::string::npos) authority = authority.substr(at + 1);
        auto colon = authority.rfind(':');
        std::string host = colon != std::string::npos && authority.find(']') == std::string::npos
                               ? authority.substr(0, colon) : authority;
        ok = !host.empty();
    }
    if (!ok) vr.addError("error parsing info url: no hostname or scheme");
}

// Go: checkPermission — "subject" or "subject queue"; queues only where permitted
inline void checkPermission(const std::string& subj, bool permitQueue, ValidationResults& vr) {
    const auto tk = splitOn(subj, ' ');
    switch (tk.size()) {
        case 1:
            validateSubject(tk[0], vr);
            break;
        case 2:
            validateSubject(tk[0], vr);
            validateSubject(tk[1], vr);
            if (!permitQueue) vr.addError("Permission Subject \"" + subj + "\" is not allowed to contain queue");
            break;
        default:
            vr.addError("Permission Subject \"" + subj + "\" contains too many spaces");
    }
}

// Go: Permissions.Validate (Resp validates nothing; Sub permits queues, Pub does not)
inline void validatePermissions(const Permissions& p, ValidationResults& vr) {
    for (const auto& s : p.sub.allow) checkPermission(s, true, vr);
    for (const auto& s : p.sub.deny) checkPermission(s, true, vr);
    for (const auto& s : p.pub.allow) checkPermission(s, false, vr);
    for (const auto& s : p.pub.deny) checkPermission(s, false, vr);
}

} // namespace jwt::internal
