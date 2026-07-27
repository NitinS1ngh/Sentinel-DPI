#pragma once
#include <string>
#include <vector>
#include <sqlite3.h>
#include <mutex>

struct ConnectionRecord {
    int id;
    std::string timestamp;
    std::string process_name;
    std::string destination_ip;
    std::string domain;
    std::string protocol;
    int port;
    long bytes_sent;
    long bytes_received;
    std::string action;
};

struct DNSRecord {
    int id;
    std::string timestamp;
    std::string src_ip;
    std::string query_name;
    std::string query_type;
    std::string process_name;
};

struct TrafficEvent {
    int id;
    std::string timestamp;
    std::string event_type;
    std::string domain;
    std::string source_ip;
    std::string destination_ip;
    std::string protocol;
};

struct DomainFrequency {
    std::string domain;
    int count;
};

struct PolicyEvent {
    int id;
    std::string timestamp;
    std::string domain;
    std::string policy_type;
    std::string source_ip;
};

struct BlockedEvent {
    int id;
    std::string timestamp;
    std::string domain;
    std::string protocol;
    std::string source_ip;
    std::string destination_ip;
    std::string reason;
};

struct FirewallAction {
    int id;
    std::string timestamp;
    std::string domain;
    std::string action;
    std::string backend;
    std::string status;
    std::string reason;
};

struct ThreatEvent {
    int id;
    std::string timestamp;
    std::string domain;
    std::string category;
    std::string severity;
    std::string description;
    std::string protocol;
    std::string source_ip;
    std::string destination_ip;
};

struct LabelFrequency {
    std::string label;
    int count;
};

struct BlockedStats {
    int blocked_today = 0;
    int blocked_dns = 0;
    int blocked_tls = 0;
    std::vector<DomainFrequency> top_domains;
};

struct TrafficStats {
    int total_dns_events = 0;
    int total_tls_events = 0;
    std::vector<DomainFrequency> top_domains;
};

struct ThreatStats {
    int total_threats_today = 0;
    std::vector<LabelFrequency> categories;
    std::vector<LabelFrequency> severity_distribution;
    std::vector<DomainFrequency> top_domains;
};

struct SecurityAnalysisRecord {
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
};

struct ThreatFeedUpdateRecord {
    int id = 0;
    std::string timestamp;
    std::string source;
    std::string status;
    int sources_checked = 0;
    int indicators_loaded = 0;
    std::string message;
};

struct ThreatFeedStatusRecord {
    int id = 0;
    std::string name;
    std::string type;
    std::string location;
    std::string status;
    std::string last_update;
    std::string next_update;
    int threat_count = 0;
    std::string version;
    std::string health;
    std::string error;
};

struct SecurityOverviewRecord {
    int total_incidents_today = 0;
    int critical_incidents = 0;
    int high_incidents = 0;
    int average_score = 0;
    int latest_score = 0;
    int active_threats = 0;
    int feed_updates_today = 0;
    std::vector<LabelFrequency> categories;
    std::vector<LabelFrequency> severities;
    std::vector<DomainFrequency> top_domains;
};

class Database {
public:
    explicit Database(const std::string &path);
    ~Database();

    bool open();
    void close();
    bool initializeSchema();

    bool insertConnection(const ConnectionRecord &rec);
    std::vector<ConnectionRecord> getConnections(int limit = 100);

    bool insertDNSQuery(const DNSRecord &rec);
    std::vector<DNSRecord> getDNSQueries(int limit = 100);

    bool insertTrafficEvent(const TrafficEvent &rec);
    std::vector<TrafficEvent> getTrafficEvents(int limit = 100, const std::string &domainFilter = "");
    TrafficStats getTrafficStats();
    std::vector<DomainFrequency> getTopDomains(int limit = 10);

    bool insertPolicyEvent(const PolicyEvent &rec);
    std::vector<PolicyEvent> getPolicyEvents(int limit = 100);

    bool insertBlockedEvent(const BlockedEvent &rec);
    std::vector<BlockedEvent> getBlockedEvents(int limit = 100);
    BlockedStats getBlockedStats();
    std::vector<DomainFrequency> getBlockedDomains(int limit = 10);

    bool insertFirewallAction(const FirewallAction &rec);
    std::vector<FirewallAction> getFirewallActions(int limit = 100);
    bool clearFirewallData();

    bool insertThreatEvent(const ThreatEvent &rec);
    std::vector<ThreatEvent> getThreatEvents(int limit = 100);
    ThreatStats getThreatStats();

    bool insertSecurityAnalysis(const SecurityAnalysisRecord &rec);
    std::vector<SecurityAnalysisRecord> getSecurityAnalyses(int limit = 100);
    SecurityOverviewRecord getSecurityOverview();

    bool insertThreatFeedUpdate(const ThreatFeedUpdateRecord &rec);
    std::vector<ThreatFeedUpdateRecord> getThreatFeedUpdates(int limit = 100);
    bool upsertThreatFeedStatus(const ThreatFeedStatusRecord &rec);
    std::vector<ThreatFeedStatusRecord> getThreatFeedStatuses(int limit = 100);

private:
    std::string dbPath;
    sqlite3 *db = nullptr;
    mutable std::recursive_mutex dbMutex;
};
