#include "PolicyEngine.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iostream>
#include <vector>

namespace {
std::string trim(const std::string &value) {
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

std::string normalizeDomain(std::string domain) {
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

bool hasSubdomainSuffix(const std::string &domain, const std::string &rule) {
    if (domain.size() <= rule.size()) {
        return false;
    }
    const size_t offset = domain.size() - rule.size();
    return domain[offset - 1] == '.' && domain.compare(offset, rule.size(), rule) == 0;
}

std::vector<std::string> collectSuffixes(const std::string &domain, bool includeSelf) {
    std::vector<std::string> suffixes;
    if (domain.empty()) {
        return suffixes;
    }

    if (includeSelf) {
        suffixes.push_back(domain);
    }

    std::size_t dot = domain.find('.');
    while (dot != std::string::npos && dot + 1 < domain.size()) {
        suffixes.push_back(domain.substr(dot + 1));
        dot = domain.find('.', dot + 1);
    }

    return suffixes;
}
} // namespace

PolicyEngine::PolicyEngine(std::string blockedPath, std::string monitoredPath)
    : blockedPolicyPath(resolvePolicyPath(blockedPath)),
      monitoredPolicyPath(resolvePolicyPath(monitoredPath)) {}

std::vector<PolicyMatch> PolicyEngine::evaluate(const std::string &domain, const std::string &sourceIp) {
    std::lock_guard<std::mutex> lock(engineMutex);
    reloadIfNeeded();

    const std::string normalizedDomain = normalizeDomain(domain);
    if (normalizedDomain.empty()) {
        return {};
    }

    std::vector<PolicyMatch> matches;
    if (matchesPolicy(normalizedDomain, blockedExactDomains, blockedWildcardDomains)) {
        std::cerr << "[POLICY] Blocked domain matched: " << normalizedDomain << "\n";
        matches.push_back({normalizedDomain, "BLOCKED", sourceIp});
    }

    if (matchesPolicy(normalizedDomain, monitoredExactDomains, monitoredWildcardDomains)) {
        std::cerr << "[POLICY] Monitored domain detected: " << normalizedDomain << "\n";
        matches.push_back({normalizedDomain, "MONITORED", sourceIp});
    }

    return matches;
}

std::vector<std::string> PolicyEngine::getBlockedRules() const {
    std::lock_guard<std::mutex> lock(engineMutex);
    std::vector<std::string> rules;
    rules.reserve(blockedExactDomains.size() + blockedWildcardDomains.size());

    for (const auto &rule : blockedExactDomains) {
        rules.push_back(rule);
    }

    for (const auto &rule : blockedWildcardDomains) {
        rules.push_back("*." + rule);
    }

    std::sort(rules.begin(), rules.end());
    return rules;
}

void PolicyEngine::reloadIfNeeded() {
    const auto blockedWrite = std::filesystem::exists(blockedPolicyPath)
        ? std::filesystem::last_write_time(blockedPolicyPath)
        : std::filesystem::file_time_type{};
    const auto monitoredWrite = std::filesystem::exists(monitoredPolicyPath)
        ? std::filesystem::last_write_time(monitoredPolicyPath)
        : std::filesystem::file_time_type{};

    if (loaded && blockedWrite == blockedLastWrite && monitoredWrite == monitoredLastWrite) {
        return;
    }

    blockedLastWrite = blockedWrite;
    monitoredLastWrite = monitoredWrite;
    blockedExactDomains.clear();
    blockedWildcardDomains.clear();
    monitoredExactDomains.clear();
    monitoredWildcardDomains.clear();

    loadFile(blockedPolicyPath, blockedExactDomains, blockedWildcardDomains);
    loadFile(monitoredPolicyPath, monitoredExactDomains, monitoredWildcardDomains);
    loaded = true;

    std::cerr << "PolicyEngine: loaded " << blockedExactDomains.size() + blockedWildcardDomains.size() << " blocked and "
              << monitoredExactDomains.size() + monitoredWildcardDomains.size() << " monitored domains\n";
}

void PolicyEngine::loadFile(const std::filesystem::path &path,
                            std::unordered_set<std::string> &exactRules,
                            std::unordered_set<std::string> &wildcardRules) {
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cerr << "PolicyEngine: policy file not found: " << path << "\n";
        return;
    }

    std::string line;
    while (std::getline(file, line)) {
        const auto commentStart = line.find('#');
        if (commentStart != std::string::npos) {
            line = line.substr(0, commentStart);
        }

        const std::string trimmed = trim(line);
        if (trimmed.rfind("*.", 0) == 0) {
            const std::string normalizedWildcard = normalizeDomain(trimmed.substr(2));
            if (!normalizedWildcard.empty()) {
                wildcardRules.insert(normalizedWildcard);
            }
            continue;
        }

        const std::string normalized = normalizeDomain(trimmed);
        if (!normalized.empty()) {
            exactRules.insert(normalized);
        }
    }
}

bool PolicyEngine::matchesPolicy(const std::string &domain,
                                 const std::unordered_set<std::string> &exactRules,
                                 const std::unordered_set<std::string> &wildcardRules) const {
    for (const auto &suffix : collectSuffixes(domain, true)) {
        if (exactRules.find(suffix) != exactRules.end()) {
            return true;
        }
    }

    for (const auto &suffix : collectSuffixes(domain, false)) {
        if (wildcardRules.find(suffix) != wildcardRules.end()) {
            return true;
        }
    }

    return false;
}

std::filesystem::path PolicyEngine::resolvePolicyPath(const std::string &path) const {
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
