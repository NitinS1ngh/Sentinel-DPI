#pragma once
#include <string>
#include <vector>
#include "Database.h"
#include "PolicyEngine.h"
#include "ThreatIntel.h"

struct SecurityAnalysis {
    int id = 0;
    std::string timestamp;
    std::string domain;
    std::string source_ip;
    std::string destination_ip;
    std::string protocol;
    std::string event_type;
    std::string category;
    std::string severity;
    std::string confidence;
    int score = 0;
    std::string explanation;
    std::string recommendation;
    std::vector<std::string> signals;
};

class SecurityIntelEngine {
public:
    SecurityAnalysis analyze(const std::string &timestamp,
                             const std::string &domain,
                             const std::string &sourceIp,
                             const std::string &destinationIp,
                             const std::string &protocol,
                             const std::string &eventType,
                             const std::vector<ThreatMatch> &threatMatches,
                             const std::vector<PolicyMatch> &policyMatches,
                             int recentObservationCount = 0) const;
};