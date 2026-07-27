#pragma once

#include <string>

struct AppConfig {
    std::string firewallBackend = "mock";
    bool threatIntelligenceEnabled = true;
    bool automaticThreatUpdatesEnabled = true;
    bool securityAnalysisEnabled = true;
    int threatUpdateIntervalSeconds = 43200;
    std::string threatFeedRegistry = "threat_feeds.json";
    std::string threatFeedOutput = "threats.json";
};

AppConfig loadAppConfig(const std::string &path = "config.json");
