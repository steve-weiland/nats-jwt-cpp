#include "jwt/claims.hpp"
#include <algorithm>
#include <cctype>

namespace jwt {

namespace {
    std::string normalizeTag(std::string_view t) {
        auto b = t.find_first_not_of(" \t\r\n");
        if (b == std::string_view::npos) return "";
        auto e = t.find_last_not_of(" \t\r\n");
        std::string out(t.substr(b, e - b + 1));
        std::transform(out.begin(), out.end(), out.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return out;
    }
}

bool tagsContain(const std::vector<std::string>& tags, std::string_view tag) {
    const std::string p = normalizeTag(tag);
    return std::find(tags.begin(), tags.end(), p) != tags.end();
}

void addTags(std::vector<std::string>& tags, const std::vector<std::string>& add) {
    for (const auto& raw : add) {
        const std::string v = normalizeTag(raw);
        if (!v.empty() && !tagsContain(tags, v)) tags.push_back(v);
    }
}

}
