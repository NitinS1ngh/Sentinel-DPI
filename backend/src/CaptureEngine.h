#pragma once
#include <atomic>
#include <thread>
#include "Database.h"
#include "BlockingEngine.h"
#include "PolicyEngine.h"
#include "ThreatIntel.h"
#include "SecurityIntel.h"
#include "EventBroadcaster.h"
#ifdef USE_PCAPPP
namespace pcpp { class RawPacket; class PcapLiveDevice; }
#endif

class CaptureEngine {
public:
    explicit CaptureEngine(Database *db,
                           const std::string &deviceName = "en0",
                           EventBroadcaster *broadcaster = nullptr,
                           BlockingEngine *blockingEngine = nullptr,
                           ThreatIntelEngine *threatIntel = nullptr,
                           SecurityIntelEngine *securityIntel = nullptr);
    ~CaptureEngine();

    PolicyEngine &getPolicyEngine() { return policyEngine; }

    // PcapPlusPlus packet callback (public so C-style callback can bind)
#ifdef USE_PCAPPP
    static void onPacketArrives(pcpp::RawPacket* rawPacket, pcpp::PcapLiveDevice* dev, void* cookie);
#endif

    void start();
    void stop();

private:
    void run();
    void captureOnInterface(const std::string &interfaceName);
    std::vector<PolicyMatch> recordPolicyMatches(const std::string &timestamp,
                                                 const std::string &domain,
                                                 const std::string &sourceIp,
                                                 const std::string &destinationIp,
                                                 const std::string &protocol);
    std::vector<ThreatMatch> recordThreatMatches(const std::string &timestamp,
                                                 const std::string &domain,
                                                 const std::string &sourceIp,
                                                 const std::string &destinationIp,
                                                 const std::string &protocol);
    void recordSecurityAnalysis(const std::string &timestamp,
                                const std::string &domain,
                                const std::string &sourceIp,
                                const std::string &destinationIp,
                                const std::string &protocol,
                                const std::string &eventType,
                                const std::vector<ThreatMatch> &threatMatches,
                                const std::vector<PolicyMatch> &policyMatches);

    Database *database;
    PolicyEngine policyEngine;
    EventBroadcaster *eventBroadcaster;
    BlockingEngine *blockingEngine;
    ThreatIntelEngine *threatIntel;
    SecurityIntelEngine *securityIntel;
    std::atomic<bool> running{false};
    std::vector<std::thread> workers;
    std::string deviceName;
};
