#include "AppConfig.h"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iostream>
#include <sstream>

namespace {
std::string trim(std::string value) {
    const auto begin = std::find_if_not(value.begin(), value.end(), [](unsigned char ch) { return std::isspace(ch); });
    const auto end = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char ch) { return std::isspace(ch); }).base();
    if (begin >= end) {
        return "";
    }
    return std::string(begin, end);
}

std::string resolveConfigPath(const std::string &path) {
    const std::string direct = path;
    std::ifstream file(direct);
    if (file.is_open()) {
        return direct;
    }

    const std::string parent = std::string("../") + path;
    std::ifstream parentFile(parent);
    if (parentFile.is_open()) {
        return parent;
    }

    return direct;
}

std::string extractStringField(const std::string &text, const std::string &name, const std::string &fallback) {
    const std::string key = "\"" + name + "\"";
    const auto keyPos = text.find(key);
    if (keyPos == std::string::npos) return fallback;
    const auto colonPos = text.find(':', keyPos + key.size());
    if (colonPos == std::string::npos) return fallback;
    const auto firstQuote = text.find('"', colonPos + 1);
    const auto secondQuote = firstQuote == std::string::npos ? std::string::npos : text.find('"', firstQuote + 1);
    if (firstQuote == std::string::npos || secondQuote == std::string::npos) return fallback;
    const std::string value = trim(text.substr(firstQuote + 1, secondQuote - firstQuote - 1));
    return value.empty() ? fallback : value;
}

bool extractBoolField(const std::string &text, const std::string &name, bool fallback) {
    const std::string key = "\"" + name + "\"";
    const auto keyPos = text.find(key);
    if (keyPos == std::string::npos) return fallback;
    const auto colonPos = text.find(':', keyPos + key.size());
    if (colonPos == std::string::npos) return fallback;
    const auto valuePos = text.find_first_not_of(" \t\r\n", colonPos + 1);
    if (valuePos == std::string::npos) return fallback;
    if (text.compare(valuePos, 4, "true") == 0) return true;
    if (text.compare(valuePos, 5, "false") == 0) return false;
    return fallback;
}

int extractIntField(const std::string &text, const std::string &name, int fallback) {
    const std::string key = "\"" + name + "\"";
    const auto keyPos = text.find(key);
    if (keyPos == std::string::npos) return fallback;
    const auto colonPos = text.find(':', keyPos + key.size());
    if (colonPos == std::string::npos) return fallback;
    const auto valuePos = text.find_first_of("-0123456789", colonPos + 1);
    if (valuePos == std::string::npos) return fallback;
    try {
        return std::stoi(text.substr(valuePos));
    } catch (...) {
        return fallback;
    }
}
} // namespace

AppConfig loadAppConfig(const std::string &path) {
    AppConfig config;
    const std::string resolvedPath = resolveConfigPath(path);

    std::ifstream file(resolvedPath);
    if (!file.is_open()) {
        std::cerr << "AppConfig: config not found, using defaults\n";
        return config;
    }

    std::ostringstream contents;
    contents << file.rdbuf();
    const std::string text = contents.str();

    config.firewallBackend = extractStringField(text, "firewall_backend", config.firewallBackend);
    config.threatIntelligenceEnabled = extractBoolField(text, "threat_intelligence_enabled", config.threatIntelligenceEnabled);
    config.automaticThreatUpdatesEnabled = extractBoolField(text, "automatic_threat_updates_enabled", config.automaticThreatUpdatesEnabled);
    config.securityAnalysisEnabled = extractBoolField(text, "security_analysis_enabled", config.securityAnalysisEnabled);
    config.threatUpdateIntervalSeconds = extractIntField(text, "threat_update_interval_seconds", config.threatUpdateIntervalSeconds);
    config.threatFeedRegistry = extractStringField(text, "threat_feed_registry", config.threatFeedRegistry);
    config.threatFeedOutput = extractStringField(text, "threat_feed_output", config.threatFeedOutput);

    return config;
}
