#include "SecurityIntel.h"
#include <algorithm>
#include <sstream>

namespace {
int scoreFromSeverity(const std::string &severity) {
    if (severity == "Critical") return 55;
    if (severity == "High") return 40;
    if (severity == "Medium") return 25;
    if (severity == "Low") return 10;
    return 15;
}

std::string normalizeSeverity(int score) {
    if (score >= 80) return "Critical";
    if (score >= 60) return "High";
    if (score >= 35) return "Medium";
    return "Low";
}

std::string confidenceFromScore(int score) {
    if (score >= 80) return "Very High";
    if (score >= 60) return "High";
    if (score >= 35) return "Moderate";
    return "Low";
}

void addSignal(std::vector<std::string> &signals, const std::string &signal) {
    if (std::find(signals.begin(), signals.end(), signal) == signals.end()) {
        signals.push_back(signal);
    }
}
} // namespace

SecurityAnalysis SecurityIntelEngine::analyze(const std::string &timestamp,
                                              const std::string &domain,
                                              const std::string &sourceIp,
                                              const std::string &destinationIp,
                                              const std::string &protocol,
                                              const std::string &eventType,
                                              const std::vector<ThreatMatch> &threatMatches,
                                              const std::vector<PolicyMatch> &policyMatches,
                                              int recentObservationCount) const {
    SecurityAnalysis analysis;
    analysis.timestamp = timestamp;
    analysis.domain = domain;
    analysis.source_ip = sourceIp;
    analysis.destination_ip = destinationIp;
    analysis.protocol = protocol;
    analysis.event_type = eventType;
    analysis.category = "Suspicious Activity";
    analysis.recommendation = "Monitor";

    int score = 18;

    for (const auto &match : threatMatches) {
        score += scoreFromSeverity(match.indicator.severity);
        if (!match.indicator.category.empty()) {
            analysis.category = match.indicator.category;
        }
        addSignal(analysis.signals, "Threat feed match: " + match.indicator.domain);
        if (!match.indicator.description.empty()) {
            addSignal(analysis.signals, match.indicator.description);
        }
    }

    for (const auto &match : policyMatches) {
        if (match.policy_type == "BLOCKED") {
            score += 24;
            addSignal(analysis.signals, "Blocked by policy engine");
            analysis.recommendation = "Block";
            if (analysis.category == "Suspicious Activity") {
                analysis.category = "Policy Enforcement";
            }
        } else {
            score += 8;
            addSignal(analysis.signals, "Policy review matched");
        }
    }

    if (recentObservationCount > 3) {
        score += std::min(18, recentObservationCount * 2);
        addSignal(analysis.signals, "Repeated activity for this domain");
    }

    score = std::clamp(score, 0, 100);
    analysis.score = score;
    analysis.severity = normalizeSeverity(score);
    analysis.confidence = confidenceFromScore(score);

    if (analysis.category == "Suspicious Activity" && !threatMatches.empty()) {
        analysis.category = threatMatches.front().indicator.category;
    }

    if (analysis.signals.empty()) {
        addSignal(analysis.signals, "No active threat or policy match detected");
    }

    std::ostringstream explanation;
    explanation << analysis.severity << " security event for " << domain << ": ";
    for (size_t i = 0; i < analysis.signals.size(); ++i) {
        if (i > 0) explanation << "; ";
        explanation << analysis.signals[i];
    }
    analysis.explanation = explanation.str();
    if (!threatMatches.empty() && score >= 80) {
        analysis.recommendation = "Block";
    } else if (score >= 60) {
        analysis.recommendation = "Investigate";
    }

    return analysis;
}