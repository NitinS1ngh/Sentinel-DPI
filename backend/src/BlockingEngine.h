#pragma once

#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "Database.h"
#include "EventBroadcaster.h"
#include "FirewallBackend.h"

struct FirewallStatus {
    std::string backend;
    std::string health;
    std::size_t activeRules = 0;
    std::string lastAction;
    std::string lastDomain;
    std::string lastStatus;
};

class BlockingEngine {
public:
    BlockingEngine(Database *database,
                   EventBroadcaster *broadcaster,
                   std::unique_ptr<FirewallBackend> backend = std::make_unique<MockFirewallBackend>());

    bool blockDomain(const std::string &domain,
                     const std::string &protocol,
                     const std::string &sourceIp,
                     const std::string &destinationIp,
                     const std::string &timestamp,
                     const std::string &reason,
                     const std::string &action = "BLOCK");

    bool unblockDomain(const std::string &domain,
                       const std::string &timestamp,
                       const std::string &reason,
                       const std::string &action = "UNBLOCK");

    bool clearActiveRules(const std::string &timestamp,
                          const std::string &reason);

    bool handleBlockedMatch(const std::string &domain,
                            const std::string &protocol,
                            const std::string &sourceIp,
                            const std::string &destinationIp,
                            const std::string &timestamp,
                            const std::string &reason);

    std::vector<std::string> getActiveRules();
    std::string getBackendName() const;
    FirewallStatus getStatus();

private:
    bool applyFirewallAction(const std::string &domain,
                             const std::string &timestamp,
                             const std::string &action,
                             const std::string &backendAction,
                             const std::string &status,
                             const std::string &reason,
                             const std::string &protocol,
                             const std::string &sourceIp,
                             const std::string &destinationIp,
                             bool persistBlockedEvent);

    std::string buildBlockedPayload(const BlockedEvent &event) const;
    std::string buildFirewallPayload(const FirewallAction &event) const;

    Database *database;
    EventBroadcaster *eventBroadcaster;
    std::unique_ptr<FirewallBackend> backend;
    std::string lastAction;
    std::string lastDomain;
    std::string lastStatus;
    mutable std::recursive_mutex engineMutex;
};