#pragma once

#include <filesystem>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

struct ThreatIndicator {
    std::string domain;
    std::string category;
    std::string severity;
    std::string description;
};

struct ThreatMatch {
    ThreatIndicator indicator;
};

class ThreatIntelEngine {
public:
    explicit ThreatIntelEngine(std::string threatPath = "threats.json");

    std::vector<ThreatIndicator> getIndicators();
    std::vector<ThreatMatch> evaluate(const std::string &domain);
    std::string getSourcePath() const;
    bool refresh();

private:
    void reloadIfNeeded();
    void loadFile();
    void clearData();

    static std::string normalizeDomain(std::string domain);
    static std::vector<std::string> suffixes(const std::string &domain, bool includeSelf);
    static bool isWildcardRule(const std::string &value);
    static std::string stripWildcard(const std::string &value);
    static std::string trim(const std::string &value);
    static std::vector<std::string> extractJsonObjects(const std::string &text);
    static std::string extractJsonStringField(const std::string &object, const std::string &key);

    std::filesystem::path resolveThreatPath(const std::string &path) const;

    std::filesystem::path threatPath;
    std::filesystem::file_time_type lastWrite{};
    bool loaded = false;
    std::vector<ThreatIndicator> indicators;
    std::unordered_map<std::string, std::vector<ThreatIndicator>> exactRules;
    std::unordered_map<std::string, std::vector<ThreatIndicator>> wildcardRules;
    std::mutex mutex;
};