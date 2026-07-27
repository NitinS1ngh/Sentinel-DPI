#pragma once
#include <atomic>
#include <cstdint>
#include <mutex>
#include <thread>
#include <string>
#include <vector>
#include "Database.h"
#include "PolicyEngine.h"
#include "ThreatIntel.h"
#include "BlockingEngine.h"
#include "EventBroadcaster.h"
#include "ThreatFeedUpdater.h"

class ApiServer {
public:
    ApiServer(Database *db,
              PolicyEngine *policyEngine = nullptr,
              ThreatIntelEngine *threatIntel = nullptr,
              BlockingEngine *firewallManager = nullptr,
              ThreatFeedUpdater *threatFeedUpdater = nullptr,
              EventBroadcaster *broadcaster = nullptr,
              int port = 8080);
    ~ApiServer();

    void start();
    void stop();

private:
    void run();
    void handleStreamClient(int clientFd, std::uint64_t lastEventId);

    Database *database;
    PolicyEngine *policyEngine;
    ThreatIntelEngine *threatIntel;
    BlockingEngine *firewallManager;
    ThreatFeedUpdater *threatFeedUpdater;
    EventBroadcaster *eventBroadcaster;
    int listenPort;
    std::atomic<bool> running{false};
    std::thread worker;
    std::mutex streamWorkersMutex;
    std::vector<std::thread> streamWorkers;
};
