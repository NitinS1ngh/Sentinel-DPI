#include "ThreatIntel.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iostream>
#include <sstream>

namespace {
bool sameIndicator(const ThreatIndicator &left, const ThreatIndicator &right) {
    return left.domain == right.domain && left.category == right.category && left.severity == right.severity;
}
} // namespace

ThreatIntelEngine::ThreatIntelEngine(std::string threatPath)
    : threatPath(resolveThreatPath(threatPath)) {}

std::string ThreatIntelEngine::trim(const std::string &value) {
    const auto begin = std::find_if_not(value.begin(), value.end(), [](unsigned char ch) {
        return std::isspace(ch);
    });
    const auto end = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char ch) {
        return std::isspace(ch);
    }).base();

    if (begin >= end) {
        return "";
    }
    return std::string(begin, end);
}

std::string ThreatIntelEngine::normalizeDomain(std::string domain) {
    domain = trim(domain);
    if (domain.rfind("*.", 0) == 0) {
        domain = domain.substr(2);
    }
    if (!domain.empty() && domain.back() == '.') {
        domain.pop_back();
    }
    std::transform(domain.begin(), domain.end(), domain.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return domain;
}

std::vector<std::string> ThreatIntelEngine::suffixes(const std::string &domain, bool includeSelf) {
    std::vector<std::string> results;
    if (domain.empty()) {
        return results;
    }

    if (includeSelf) {
        results.push_back(domain);
    }

    std::size_t dot = domain.find('.');
    while (dot != std::string::npos && dot + 1 < domain.size()) {
        results.push_back(domain.substr(dot + 1));
        dot = domain.find('.', dot + 1);
    }

    return results;
}

bool ThreatIntelEngine::isWildcardRule(const std::string &value) {
    return trim(value).rfind("*.", 0) == 0;
}

std::string ThreatIntelEngine::stripWildcard(const std::string &value) {
    const std::string trimmed = trim(value);
    return trimmed.rfind("*.", 0) == 0 ? trimmed.substr(2) : trimmed;
}

std::vector<std::string> ThreatIntelEngine::extractJsonObjects(const std::string &text) {
    std::vector<std::string> objects;
    bool inString = false;
    bool escape = false;
    int depth = 0;
    std::size_t start = std::string::npos;

    for (std::size_t index = 0; index < text.size(); ++index) {
        const char ch = text[index];
        if (escape) {
            escape = false;
            continue;
        }

        if (ch == '\\' && inString) {
            escape = true;
            continue;
        }

        if (ch == '"') {
            inString = !inString;
            continue;
        }

        if (inString) {
            continue;
        }

        if (ch == '{') {
            if (depth == 0) {
                start = index;
            }
            ++depth;
        } else if (ch == '}') {
            --depth;
            if (depth == 0 && start != std::string::npos) {
                objects.push_back(text.substr(start, index - start + 1));
                start = std::string::npos;
            }
        }
    }

    return objects;
}

std::string ThreatIntelEngine::extractJsonStringField(const std::string &object, const std::string &key) {
    const std::string needle = "\"" + key + "\"";
    const auto keyPos = object.find(needle);
    if (keyPos == std::string::npos) {
        return "";
    }

    const auto colonPos = object.find(':', keyPos + needle.size());
    if (colonPos == std::string::npos) {
        return "";
    }

    const auto firstQuote = object.find('"', colonPos + 1);
    if (firstQuote == std::string::npos) {
        return "";
    }

    std::string value;
    bool escape = false;
    for (std::size_t index = firstQuote + 1; index < object.size(); ++index) {
        const char ch = object[index];
        if (escape) {
            value.push_back(ch);
            escape = false;
            continue;
        }
        if (ch == '\\') {
            escape = true;
            continue;
        }
        if (ch == '"') {
            break;
        }
        value.push_back(ch);
    }

    return value;
}

std::filesystem::path ThreatIntelEngine::resolveThreatPath(const std::string &path) const {
    const std::filesystem::path direct(path);
    if (std::filesystem::exists(direct)) {
        return direct;
    }

    const std::filesystem::path parent = std::filesystem::path("..") / path;
    if (std::filesystem::exists(parent)) {
        return parent;
    }

    return direct;
}

void ThreatIntelEngine::clearData() {
    indicators.clear();
    exactRules.clear();
    wildcardRules.clear();
}

void ThreatIntelEngine::loadFile() {
    std::ifstream file(threatPath);
    if (!file.is_open()) {
        std::cerr << "ThreatIntel: threat file not found: " << threatPath << "\n";
        clearData();
        return;
    }

    std::ostringstream contents;
    contents << file.rdbuf();
    const std::string text = contents.str();

    clearData();
    for (const auto &object : extractJsonObjects(text)) {
        ThreatIndicator indicator;
        const std::string rawDomain = trim(extractJsonStringField(object, "domain"));
        indicator.domain = rawDomain;
        indicator.category = trim(extractJsonStringField(object, "category"));
        indicator.severity = trim(extractJsonStringField(object, "severity"));
        indicator.description = trim(extractJsonStringField(object, "description"));

        if (rawDomain.empty()) {
            continue;
        }

        indicators.push_back(indicator);
        const std::string normalizedRule = normalizeDomain(stripWildcard(rawDomain));
        if (isWildcardRule(rawDomain)) {
            wildcardRules[normalizedRule].push_back(indicator);
        } else {
            exactRules[normalizedRule].push_back(indicator);
        }
    }

    std::cerr << "ThreatIntel: loaded " << indicators.size() << " indicators\n";
}

void ThreatIntelEngine::reloadIfNeeded() {
    const auto writeTime = std::filesystem::exists(threatPath)
        ? std::filesystem::last_write_time(threatPath)
        : std::filesystem::file_time_type{};

    if (loaded && writeTime == lastWrite) {
        return;
    }

    lastWrite = writeTime;
    loadFile();
    loaded = true;
}

std::vector<ThreatIndicator> ThreatIntelEngine::getIndicators() {
    std::lock_guard<std::mutex> lock(mutex);
    reloadIfNeeded();
    return indicators;
}

std::vector<ThreatMatch> ThreatIntelEngine::evaluate(const std::string &domain) {
    std::lock_guard<std::mutex> lock(mutex);
    reloadIfNeeded();

    const std::string normalized = normalizeDomain(domain);
    if (normalized.empty()) {
        return {};
    }

    std::vector<ThreatMatch> matches;
    std::vector<std::string> exactCandidates = suffixes(normalized, true);
    for (const auto &candidate : exactCandidates) {
        const auto exactIt = exactRules.find(candidate);
        if (exactIt != exactRules.end()) {
            for (const auto &indicator : exactIt->second) {
                const bool alreadyPresent = std::any_of(matches.begin(), matches.end(), [&](const ThreatMatch &match) {
                    return sameIndicator(match.indicator, indicator);
                });
                if (!alreadyPresent) {
                    matches.push_back({indicator});
                }
            }
        }
    }

    for (const auto &candidate : suffixes(normalized, false)) {
        const auto wildcardIt = wildcardRules.find(candidate);
        if (wildcardIt != wildcardRules.end()) {
            for (const auto &indicator : wildcardIt->second) {
                matches.push_back({indicator});
            }
        }
    }

    return matches;
}

std::string ThreatIntelEngine::getSourcePath() const {
    return threatPath.string();
}

bool ThreatIntelEngine::refresh() {
    std::lock_guard<std::mutex> lock(mutex);
    loaded = false;
    reloadIfNeeded();
    return loaded;
}
