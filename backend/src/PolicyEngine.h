#pragma once

#include <filesystem>
#include <mutex>
#include <string>
#include <unordered_set>
#include <vector>

struct PolicyMatch {
    std::string domain;
    std::string policy_type;
    std::string source_ip;
};

class PolicyEngine {
public:
    PolicyEngine(std::string blockedPath = "blocked_domains.txt",
                 std::string monitoredPath = "monitored_domains.txt");

    std::vector<PolicyMatch> evaluate(const std::string &domain, const std::string &sourceIp);
    std::vector<std::string> getBlockedRules() const;

private:
    void reloadIfNeeded();
    void loadFile(const std::filesystem::path &path,
                  std::unordered_set<std::string> &exactRules,
                  std::unordered_set<std::string> &wildcardRules);
    bool matchesPolicy(const std::string &domain,
                       const std::unordered_set<std::string> &exactRules,
                       const std::unordered_set<std::string> &wildcardRules) const;
    std::filesystem::path resolvePolicyPath(const std::string &path) const;

    std::filesystem::path blockedPolicyPath;
    std::filesystem::path monitoredPolicyPath;
    std::filesystem::file_time_type blockedLastWrite{};
    std::filesystem::file_time_type monitoredLastWrite{};
    bool loaded = false;
    std::unordered_set<std::string> blockedExactDomains;
    std::unordered_set<std::string> blockedWildcardDomains;
    std::unordered_set<std::string> monitoredExactDomains;
    std::unordered_set<std::string> monitoredWildcardDomains;
    mutable std::mutex engineMutex;
};
