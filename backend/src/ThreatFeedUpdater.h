#pragma once
#include <atomic>
#include <string>
#include <thread>
#include <vector>
#include "Database.h"
#include "EventBroadcaster.h"
#include "ThreatIntel.h"

struct ThreatFeedSource {
    std::string name;
    std::string path;
    std::string type = "json";
    std::string url;
    std::string version = "local";
    bool enabled = true;
};

struct ThreatFeedUpdateResult {
    bool ok = false;
    std::string timestamp;
    std::string message;
    int sources_checked = 0;
    int indicators_loaded = 0;
    int indicators_written = 0;
};

class ThreatFeedUpdater {
public:
    ThreatFeedUpdater(Database *database,
                      ThreatIntelEngine *threatIntel,
                      EventBroadcaster *eventBroadcaster = nullptr,
                      const std::string &registryPath = "threat_feeds.json",
                      const std::string &outputPath = "threats.json",
                      int intervalSeconds = 300);
    ~ThreatFeedUpdater();

    void start();
    void stop();
    ThreatFeedUpdateResult refreshNow();

    std::vector<ThreatFeedSource> getSources() const;
    int getIntervalSeconds() const;

private:
    void run();
    bool loadRegistry(std::vector<ThreatFeedSource> &out, std::string &error) const;
    bool loadIndicatorsFile(const std::string &path, std::vector<ThreatIndicator> &out, std::string &error) const;
    bool loadDomainListFile(const std::string &path, std::vector<ThreatIndicator> &out, const ThreatFeedSource &source, std::string &error) const;
    bool loadIndicatorsFromSource(const ThreatFeedSource &source, std::vector<ThreatIndicator> &out, std::string &error) const;
    bool downloadToFile(const std::string &url, const std::string &path, std::string &error) const;
    bool writeIndicatorsFile(const std::vector<ThreatIndicator> &indicators, std::string &error) const;
    ThreatFeedUpdateResult performRefresh();

    Database *database;
    ThreatIntelEngine *threatIntel;
    EventBroadcaster *eventBroadcaster;
    std::string registryPath;
    std::string outputPath;
    int intervalSeconds;
    std::atomic<bool> running{false};
    std::thread worker;
    mutable std::vector<ThreatFeedSource> sourcesCache;
};
