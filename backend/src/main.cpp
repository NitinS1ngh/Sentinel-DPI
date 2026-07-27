#include <iostream>
#include <thread>
#include "Database.h"
#include "CaptureEngine.h"
#include "ApiServer.h"
#include "EventBroadcaster.h"
#include "BlockingEngine.h"
#include "AppConfig.h"
#include "FirewallBackend.h"
#include "ThreatIntel.h"
#include "SecurityIntel.h"
#include "ThreatFeedUpdater.h"

int main(int argc, char** argv) {
    std::cout << "Sentinel DPI - daemon starting\n";

    Database db("sentinel.db");
    if (!db.open()) {
        std::cerr << "Failed to open database\n";
        return 1;
    }
    db.initializeSchema();

    const AppConfig config = loadAppConfig();
    std::cout << "Firewall backend preference: " << config.firewallBackend << "\n";
    auto firewallBackend = createFirewallBackend(config.firewallBackend);
    ThreatIntelEngine threatIntel(config.threatFeedOutput);
    SecurityIntelEngine securityIntel;

    std::string deviceName = "en0";
    if (argc > 1) deviceName = argv[1];
    std::cout << "Capture device preference: " << deviceName << "\n";
    EventBroadcaster broadcaster;
    BlockingEngine blockingEngine(&db, &broadcaster, std::move(firewallBackend));
    ThreatFeedUpdater threatFeedUpdater(
        &db,
        &threatIntel,
        &broadcaster,
        config.threatFeedRegistry,
        config.threatFeedOutput,
        config.threatUpdateIntervalSeconds
    );
    if (config.threatIntelligenceEnabled && config.automaticThreatUpdatesEnabled) {
        threatFeedUpdater.start();
    }

    CaptureEngine capture(
        &db,
        deviceName,
        &broadcaster,
        &blockingEngine,
        config.threatIntelligenceEnabled ? &threatIntel : nullptr,
        config.securityAnalysisEnabled ? &securityIntel : nullptr
    );
    capture.start();

    ApiServer api(
        &db,
        &capture.getPolicyEngine(),
        config.threatIntelligenceEnabled ? &threatIntel : nullptr,
        &blockingEngine,
        config.threatIntelligenceEnabled ? &threatFeedUpdater : nullptr,
        &broadcaster,
        8080
    );
    api.start();

    std::cout << "Press Enter to stop...\n";
    std::cin.get();

    api.stop();
    capture.stop();
    threatFeedUpdater.stop();
    db.close();

    std::cout << "Sentinel DPI - daemon stopped\n";
    return 0;
}
