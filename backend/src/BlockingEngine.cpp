#include "BlockingEngine.h"

#include <iostream>
#include <sstream>
#include <utility>

namespace {
std::string escapeJson(const std::string &value) {
    std::string escaped;
    escaped.reserve(value.size());
    for (char ch : value) {
        unsigned char u = static_cast<unsigned char>(ch);
        switch (ch) {
            case '\\': escaped += "\\\\"; break;
            case '"': escaped += "\\\""; break;
            case '\b': escaped += "\\b"; break;
            case '\f': escaped += "\\f"; break;
            case '\n': escaped += "\\n"; break;
            case '\r': escaped += "\\r"; break;
            case '\t': escaped += "\\t"; break;
            default:
                if (u < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", u);
                    escaped += buf;
                } else {
                    escaped.push_back(ch);
                }
                break;
        }
    }
    return escaped;
}
} // namespace

BlockingEngine::BlockingEngine(Database *database,
                               EventBroadcaster *broadcaster,
                               std::unique_ptr<FirewallBackend> backend)
    : database(database), eventBroadcaster(broadcaster), backend(std::move(backend)) {}

std::string BlockingEngine::buildBlockedPayload(const BlockedEvent &event) const {
    std::ostringstream ss;
    ss << "{";
    ss << "\"type\":\"BLOCKED\",";
    ss << "\"domain\":\"" << escapeJson(event.domain) << "\",";
    ss << "\"timestamp\":\"" << escapeJson(event.timestamp) << "\",";
    ss << "\"source_ip\":\"" << escapeJson(event.source_ip) << "\",";
    ss << "\"destination_ip\":\"" << escapeJson(event.destination_ip) << "\",";
    ss << "\"protocol\":\"" << escapeJson(event.protocol) << "\",";
    ss << "\"reason\":\"" << escapeJson(event.reason) << "\"";
    ss << "}";
    return ss.str();
}

std::string BlockingEngine::buildFirewallPayload(const FirewallAction &event) const {
    std::ostringstream ss;
    ss << "{";
    ss << "\"type\":\"FIREWALL\",";
    ss << "\"domain\":\"" << escapeJson(event.domain) << "\",";
    ss << "\"timestamp\":\"" << escapeJson(event.timestamp) << "\",";
    ss << "\"action\":\"" << escapeJson(event.action) << "\",";
    ss << "\"backend\":\"" << escapeJson(event.backend) << "\",";
    ss << "\"status\":\"" << escapeJson(event.status) << "\",";
    ss << "\"reason\":\"" << escapeJson(event.reason) << "\"";
    ss << "}";
    return ss.str();
}

bool BlockingEngine::applyFirewallAction(const std::string &domain,
                                         const std::string &timestamp,
                                         const std::string &action,
                                         const std::string &backendAction,
                                         const std::string &status,
                                         const std::string &reason,
                                         const std::string &protocol,
                                         const std::string &sourceIp,
                                         const std::string &destinationIp,
                                         bool persistBlockedEvent) {
    std::lock_guard<std::recursive_mutex> lock(engineMutex);
    if (backend == nullptr) {
        return false;
    }

    const bool backendSuccess = backendAction == "BLOCK"
        ? backend->blockDomain(domain)
        : backend->unblockDomain(domain);

    FirewallAction firewallAction;
    firewallAction.timestamp = timestamp;
    firewallAction.domain = domain;
    firewallAction.action = action;
    firewallAction.backend = backend->name();
    firewallAction.status = backendSuccess ? status : "FAILED";
    firewallAction.reason = reason;

    if (backendSuccess) {
        std::cerr << "[BLOCK] Rule Matched\n";
        if (database != nullptr && database->insertFirewallAction(firewallAction)) {
            std::cerr << "[BLOCK] Event Stored\n";
        }

        if (persistBlockedEvent) {
            BlockedEvent blockedEvent;
            blockedEvent.timestamp = timestamp;
            blockedEvent.domain = domain;
            blockedEvent.protocol = protocol;
            blockedEvent.source_ip = sourceIp;
            blockedEvent.destination_ip = destinationIp;
            blockedEvent.reason = reason;
            if (database != nullptr) {
                database->insertBlockedEvent(blockedEvent);
            }

            if (eventBroadcaster != nullptr) {
                eventBroadcaster->broadcast(buildBlockedPayload(blockedEvent));
            }
        }

        if (eventBroadcaster != nullptr) {
            eventBroadcaster->broadcast(buildFirewallPayload(firewallAction));
            std::cerr << "[BLOCK] Dashboard Updated\n";
        }

        lastAction = action;
        lastDomain = domain;
        lastStatus = firewallAction.status;
        return true;
    }

    firewallAction.status = "FAILED";
    if (database != nullptr) {
        database->insertFirewallAction(firewallAction);
    }

    lastAction = action;
    lastDomain = domain;
    lastStatus = firewallAction.status;
    return false;
}

bool BlockingEngine::handleBlockedMatch(const std::string &domain,
                                        const std::string &protocol,
                                        const std::string &sourceIp,
                                        const std::string &destinationIp,
                                        const std::string &timestamp,
                                        const std::string &reason) {
    std::lock_guard<std::recursive_mutex> lock(engineMutex);
    return applyFirewallAction(domain, timestamp, "BLOCK", "BLOCK", "SUCCESS", reason, protocol, sourceIp, destinationIp, true);
}

bool BlockingEngine::blockDomain(const std::string &domain,
                                 const std::string &protocol,
                                 const std::string &sourceIp,
                                 const std::string &destinationIp,
                                 const std::string &timestamp,
                                 const std::string &reason,
                                 const std::string &action) {
    std::lock_guard<std::recursive_mutex> lock(engineMutex);
    return applyFirewallAction(domain, timestamp, action, "BLOCK", "SUCCESS", reason, protocol, sourceIp, destinationIp, false);
}

bool BlockingEngine::unblockDomain(const std::string &domain,
                                   const std::string &timestamp,
                                   const std::string &reason,
                                   const std::string &action) {
    std::lock_guard<std::recursive_mutex> lock(engineMutex);
    return applyFirewallAction(domain, timestamp, action, "UNBLOCK", "SUCCESS", reason, "", "", "", false);
}

bool BlockingEngine::clearActiveRules(const std::string &timestamp, const std::string &reason) {
    std::lock_guard<std::recursive_mutex> lock(engineMutex);
    if (backend == nullptr) {
        return false;
    }

    const bool backendSuccess = backend->clearRules();
    if (backendSuccess) {
        if (database != nullptr) {
            database->clearFirewallData();
        }

        if (eventBroadcaster != nullptr) {
            eventBroadcaster->broadcast("{\"type\":\"FIREWALL_CLEAR\"}");
        }

        lastAction = "CLEAR";
        lastDomain = "";
        lastStatus = "SUCCESS";
        return true;
    }
    return false;
}

std::vector<std::string> BlockingEngine::getActiveRules() {
    std::lock_guard<std::recursive_mutex> lock(engineMutex);
    return backend ? backend->getBlockedDomains() : std::vector<std::string>{};
}

std::string BlockingEngine::getBackendName() const {
    std::lock_guard<std::recursive_mutex> lock(engineMutex);
    return backend ? backend->name() : "Unknown";
}

FirewallStatus BlockingEngine::getStatus() {
    std::lock_guard<std::recursive_mutex> lock(engineMutex);
    FirewallStatus status;
    status.backend = getBackendName();
    status.activeRules = backend ? backend->getBlockedDomains().size() : 0;
    status.health = lastStatus == "FAILED" ? "Degraded" : "Healthy";
    status.lastAction = lastAction;
    status.lastDomain = lastDomain;
    status.lastStatus = lastStatus.empty() ? "UNKNOWN" : lastStatus;
    return status;
}