#include "ApiServer.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <iostream>
#include <sstream>
#include <vector>
#include <chrono>
#include <cctype>
#include <cstring>
#include <ctime>

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

std::string currentUtcTimestamp() {
    std::time_t now = std::time(nullptr);
    char buffer[32];
    std::tm tmUtc{};
#if defined(_WIN32)
    gmtime_s(&tmUtc, &now);
#else
    gmtime_r(&now, &tmUtc);
#endif
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tmUtc);
    return buffer;
}

std::string getQueryParam(const std::string &request, const std::string &key) {
    const std::string needle = key + "=";
    const auto pos = request.find(needle);
    if (pos == std::string::npos) {
        return "";
    }

    const auto start = pos + needle.size();
    const auto end = request.find_first_of(" &\r\n", start);
    return request.substr(start, end == std::string::npos ? std::string::npos : end - start);
}

std::string urlDecode(const std::string &src) {
    std::string ret;
    ret.reserve(src.length());
    for (size_t i = 0; i < src.length(); ++i) {
        if (src[i] == '%') {
            if (i + 2 < src.length()) {
                int value = 0;
                std::istringstream hexStream(src.substr(i + 1, 2));
                if (hexStream >> std::hex >> value) {
                    ret += static_cast<char>(value);
                    i += 2;
                } else {
                    ret += '%';
                }
            } else {
                ret += '%';
            }
        } else if (src[i] == '+') {
            ret += ' ';
        } else {
            ret += src[i];
        }
    }
    return ret;
}

std::string extractHost(std::string input) {
    const auto first = input.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    const auto last = input.find_last_not_of(" \t\r\n");
    input = input.substr(first, last - first + 1);

    if (input.rfind("https://", 0) == 0) {
        input = input.substr(8);
    } else if (input.rfind("http://", 0) == 0) {
        input = input.substr(7);
    }

    const auto slash = input.find('/');
    if (slash != std::string::npos) {
        input = input.substr(0, slash);
    }
    const auto colon = input.find(':');
    if (colon != std::string::npos) {
        input = input.substr(0, colon);
    }
    const auto question = input.find('?');
    if (question != std::string::npos) {
        input = input.substr(0, question);
    }
    return input;
}


std::string toLowerCopy(std::string value) {
    for (char &ch : value) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return value;
}

std::string getHeaderValue(const std::string &request, const std::string &headerName) {
    const std::string target = toLowerCopy(headerName);
    std::istringstream lines(request);
    std::string line;

    std::getline(lines, line);
    while (std::getline(lines, line)) {
        if (line == "\r" || line.empty()) {
            break;
        }

        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        const auto colonPos = line.find(':');
        if (colonPos == std::string::npos) {
            continue;
        }

        std::string key = toLowerCopy(line.substr(0, colonPos));
        if (key != target) {
            continue;
        }

        std::string value = line.substr(colonPos + 1);
        const auto first = value.find_first_not_of(' ');
        if (first == std::string::npos) {
            return "";
        }
        const auto last = value.find_last_not_of(' ');
        return value.substr(first, last - first + 1);
    }

    return "";
}

std::uint64_t parseEventId(const std::string &request) {
    const std::string headerValue = getHeaderValue(request, "Last-Event-ID");
    if (headerValue.empty()) {
        return 0;
    }

    try {
        return static_cast<std::uint64_t>(std::stoull(headerValue));
    } catch (...) {
        return 0;
    }
}

std::string buildJsonForTrafficEvents(const std::vector<TrafficEvent> &rows) {
    std::ostringstream ss;
    ss << "[";
    bool first = true;
    for (const auto &r : rows) {
        if (!first) ss << ",";
        first = false;
        ss << "{"
           << "\"id\":" << r.id << ","
           << "\"timestamp\":\"" << escapeJson(r.timestamp) << "\"," 
           << "\"event_type\":\"" << escapeJson(r.event_type) << "\"," 
           << "\"domain\":\"" << escapeJson(r.domain) << "\"," 
           << "\"source_ip\":\"" << escapeJson(r.source_ip) << "\"," 
           << "\"destination_ip\":\"" << escapeJson(r.destination_ip) << "\"," 
           << "\"protocol\":\"" << escapeJson(r.protocol) << "\""
           << "}";
    }
    ss << "]";
    return ss.str();
}

std::string buildJsonForDomainFrequency(const std::vector<DomainFrequency> &rows) {
    std::ostringstream ss;
    ss << "[";
    bool first = true;
    for (const auto &r : rows) {
        if (!first) ss << ",";
        first = false;
        ss << "{"
           << "\"domain\":\"" << escapeJson(r.domain) << "\"," 
           << "\"count\":" << r.count
           << "}";
    }
    ss << "]";
    return ss.str();
}

std::string buildJsonForStats(const TrafficStats &stats) {
    std::ostringstream ss;
    ss << "{";
    ss << "\"total_dns_events\":" << stats.total_dns_events << ",";
    ss << "\"total_tls_events\":" << stats.total_tls_events << ",";
    ss << "\"top_domains\":" << buildJsonForDomainFrequency(stats.top_domains);
    ss << "}";
    return ss.str();
}

std::string buildJsonForPolicyEvents(const std::vector<PolicyEvent> &rows) {
    std::ostringstream ss;
    ss << "[";
    bool first = true;
    for (const auto &r : rows) {
        if (!first) ss << ",";
        first = false;
        ss << "{"
           << "\"id\":" << r.id << ","
           << "\"timestamp\":\"" << escapeJson(r.timestamp) << "\","
           << "\"domain\":\"" << escapeJson(r.domain) << "\","
           << "\"policy_type\":\"" << escapeJson(r.policy_type) << "\","
           << "\"source_ip\":\"" << escapeJson(r.source_ip) << "\""
           << "}";
    }
    ss << "]";
    return ss.str();
}

std::string buildJsonForBlockedEvents(const std::vector<BlockedEvent> &rows) {
    std::ostringstream ss;
    ss << "[";
    bool first = true;
    for (const auto &r : rows) {
        if (!first) ss << ",";
        first = false;
        ss << "{"
           << "\"id\":" << r.id << ","
           << "\"timestamp\":\"" << escapeJson(r.timestamp) << "\"," 
           << "\"domain\":\"" << escapeJson(r.domain) << "\"," 
           << "\"protocol\":\"" << escapeJson(r.protocol) << "\"," 
           << "\"source_ip\":\"" << escapeJson(r.source_ip) << "\"," 
           << "\"destination_ip\":\"" << escapeJson(r.destination_ip) << "\"," 
           << "\"reason\":\"" << escapeJson(r.reason) << "\""
           << "}";
    }
    ss << "]";
    return ss.str();
}

std::string buildJsonForBlockedStats(const BlockedStats &stats) {
    std::ostringstream ss;
    ss << "{";
    ss << "\"blocked_today\":" << stats.blocked_today << ",";
    ss << "\"blocked_dns\":" << stats.blocked_dns << ",";
    ss << "\"blocked_tls\":" << stats.blocked_tls << ",";
    ss << "\"most_blocked_domains\":" << buildJsonForDomainFrequency(stats.top_domains);
    ss << "}";
    return ss.str();
}

std::string buildJsonForStringArray(const std::vector<std::string> &values) {
    std::ostringstream ss;
    ss << "[";
    bool first = true;
    for (const auto &value : values) {
        if (!first) ss << ",";
        first = false;
        ss << "\"" << escapeJson(value) << "\"";
    }
    ss << "]";
    return ss.str();
}

std::string buildJsonForFirewallActions(const std::vector<FirewallAction> &rows) {
    std::ostringstream ss;
    ss << "[";
    bool first = true;
    for (const auto &r : rows) {
        if (!first) ss << ",";
        first = false;
        ss << "{"
           << "\"id\":" << r.id << ","
           << "\"timestamp\":\"" << escapeJson(r.timestamp) << "\"," 
           << "\"domain\":\"" << escapeJson(r.domain) << "\"," 
           << "\"action\":\"" << escapeJson(r.action) << "\"," 
           << "\"backend\":\"" << escapeJson(r.backend) << "\"," 
           << "\"status\":\"" << escapeJson(r.status) << "\"," 
           << "\"reason\":\"" << escapeJson(r.reason) << "\""
           << "}";
    }
    ss << "]";
    return ss.str();
}

std::string buildJsonForLabelFrequency(const std::vector<LabelFrequency> &rows) {
    std::ostringstream ss;
    ss << "[";
    bool first = true;
    for (const auto &r : rows) {
        if (!first) ss << ",";
        first = false;
        ss << "{"
           << "\"label\":\"" << escapeJson(r.label) << "\"," 
           << "\"count\":" << r.count
           << "}";
    }
    ss << "]";
    return ss.str();
}

std::string buildJsonForThreatEvents(const std::vector<ThreatEvent> &rows) {
    std::ostringstream ss;
    ss << "[";
    bool first = true;
    for (const auto &r : rows) {
        if (!first) ss << ",";
        first = false;
        ss << "{"
           << "\"id\":" << r.id << ","
           << "\"timestamp\":\"" << escapeJson(r.timestamp) << "\"," 
           << "\"domain\":\"" << escapeJson(r.domain) << "\"," 
           << "\"category\":\"" << escapeJson(r.category) << "\"," 
           << "\"severity\":\"" << escapeJson(r.severity) << "\"," 
           << "\"description\":\"" << escapeJson(r.description) << "\"," 
           << "\"protocol\":\"" << escapeJson(r.protocol) << "\"," 
           << "\"source_ip\":\"" << escapeJson(r.source_ip) << "\"," 
           << "\"destination_ip\":\"" << escapeJson(r.destination_ip) << "\""
           << "}";
    }
    ss << "]";
    return ss.str();
}

std::string buildJsonForThreatIndicators(const std::vector<ThreatIndicator> &rows) {
    std::ostringstream ss;
    ss << "[";
    bool first = true;
    for (const auto &r : rows) {
        if (!first) ss << ",";
        first = false;
        ss << "{"
           << "\"domain\":\"" << escapeJson(r.domain) << "\"," 
           << "\"category\":\"" << escapeJson(r.category) << "\"," 
           << "\"severity\":\"" << escapeJson(r.severity) << "\"," 
           << "\"description\":\"" << escapeJson(r.description) << "\""
           << "}";
    }
    ss << "]";
    return ss.str();
}

std::string buildJsonForThreatStats(const ThreatStats &stats) {
    std::ostringstream ss;
    ss << "{";
    ss << "\"total_threats_today\":" << stats.total_threats_today << ",";
    ss << "\"categories\":" << buildJsonForLabelFrequency(stats.categories) << ",";
    ss << "\"severity_distribution\":" << buildJsonForLabelFrequency(stats.severity_distribution) << ",";
    ss << "\"top_domains\":" << buildJsonForDomainFrequency(stats.top_domains);
    ss << "}";
    return ss.str();
}

std::string buildJsonForSecurityAnalyses(const std::vector<SecurityAnalysisRecord> &rows) {
    std::ostringstream ss;
    ss << "[";
    bool first = true;
    for (const auto &r : rows) {
        if (!first) ss << ",";
        first = false;
        ss << "{"
           << "\"id\":" << r.id << ","
           << "\"timestamp\":\"" << escapeJson(r.timestamp) << "\","
           << "\"domain\":\"" << escapeJson(r.domain) << "\","
           << "\"source_ip\":\"" << escapeJson(r.source_ip) << "\","
           << "\"destination_ip\":\"" << escapeJson(r.destination_ip) << "\","
           << "\"protocol\":\"" << escapeJson(r.protocol) << "\","
           << "\"event_type\":\"" << escapeJson(r.event_type) << "\","
           << "\"category\":\"" << escapeJson(r.category) << "\","
           << "\"severity\":\"" << escapeJson(r.severity) << "\","
           << "\"confidence\":\"" << escapeJson(r.confidence) << "\","
           << "\"score\":" << r.score << ","
           << "\"explanation\":\"" << escapeJson(r.explanation) << "\","
           << "\"recommendation\":\"" << escapeJson(r.recommendation) << "\""
           << "}";
    }
    ss << "]";
    return ss.str();
}

std::string buildJsonForSecurityOverview(const SecurityOverviewRecord &overview) {
    std::ostringstream ss;
    ss << "{";
    ss << "\"total_incidents_today\":" << overview.total_incidents_today << ",";
    ss << "\"critical_incidents\":" << overview.critical_incidents << ",";
    ss << "\"high_incidents\":" << overview.high_incidents << ",";
    ss << "\"average_score\":" << overview.average_score << ",";
    ss << "\"latest_score\":" << overview.latest_score << ",";
    ss << "\"active_threats\":" << overview.active_threats << ",";
    ss << "\"feed_updates_today\":" << overview.feed_updates_today << ",";
    ss << "\"categories\":" << buildJsonForLabelFrequency(overview.categories) << ",";
    ss << "\"severities\":" << buildJsonForLabelFrequency(overview.severities) << ",";
    ss << "\"top_domains\":" << buildJsonForDomainFrequency(overview.top_domains);
    ss << "}";
    return ss.str();
}

std::string buildJsonForFeedUpdates(const std::vector<ThreatFeedUpdateRecord> &rows) {
    std::ostringstream ss;
    ss << "[";
    bool first = true;
    for (const auto &r : rows) {
        if (!first) ss << ",";
        first = false;
        ss << "{"
           << "\"id\":" << r.id << ","
           << "\"timestamp\":\"" << escapeJson(r.timestamp) << "\","
           << "\"source\":\"" << escapeJson(r.source) << "\","
           << "\"status\":\"" << escapeJson(r.status) << "\","
           << "\"sources_checked\":" << r.sources_checked << ","
           << "\"indicators_loaded\":" << r.indicators_loaded << ","
           << "\"message\":\"" << escapeJson(r.message) << "\""
           << "}";
    }
    ss << "]";
    return ss.str();
}

std::string buildJsonForFeedSources(const std::vector<ThreatFeedStatusRecord> &feeds,
                                    const std::vector<ThreatFeedUpdateRecord> &updates,
                                    int intervalSeconds,
                                    int threatCount) {
    std::ostringstream ss;
    const std::string lastUpdate = updates.empty() ? "" : updates.front().timestamp;
    const std::string status = updates.empty() ? "Pending" : updates.front().status;
    const std::string health = updates.empty() ? "Unknown" : (updates.front().status == "REFRESHED" ? "Healthy" : "Degraded");
    ss << "{";
    ss << "\"auto_refresh_enabled\":true,";
    ss << "\"update_interval_seconds\":" << intervalSeconds << ",";
    ss << "\"threat_count\":" << threatCount << ",";
    ss << "\"last_update\":\"" << escapeJson(lastUpdate) << "\",";
    ss << "\"status\":\"" << escapeJson(status) << "\",";
    ss << "\"health\":\"" << escapeJson(health) << "\",";
    ss << "\"feeds\":[";
    bool first = true;
    for (const auto &feed : feeds) {
        if (!first) ss << ",";
        first = false;
        const bool enabled = feed.status != "DISABLED";
        ss << "{"
           << "\"id\":" << feed.id << ","
           << "\"name\":\"" << escapeJson(feed.name) << "\","
           << "\"type\":\"" << escapeJson(feed.type) << "\","
           << "\"location\":\"" << escapeJson(feed.location) << "\","
           << "\"enabled\":" << (enabled ? "true" : "false") << ","
           << "\"status\":\"" << escapeJson(feed.status.empty() ? "Pending" : feed.status) << "\","
           << "\"last_update\":\"" << escapeJson(feed.last_update) << "\","
           << "\"next_update\":\"" << escapeJson(feed.next_update) << "\","
           << "\"threat_count\":" << feed.threat_count << ","
           << "\"version\":\"" << escapeJson(feed.version) << "\","
           << "\"health\":\"" << escapeJson(feed.health.empty() ? "Unknown" : feed.health) << "\","
           << "\"error\":\"" << escapeJson(feed.error) << "\""
           << "}";
    }
    ss << "],";
    ss << "\"updates\":" << buildJsonForFeedUpdates(updates);
    ss << "}";
    return ss.str();
}
} // namespace

ApiServer::ApiServer(Database *db, PolicyEngine *policyEngine, ThreatIntelEngine *threatIntel, BlockingEngine *firewallManager, ThreatFeedUpdater *threatFeedUpdater, EventBroadcaster *broadcaster, int port)
    : database(db), policyEngine(policyEngine), threatIntel(threatIntel), firewallManager(firewallManager), threatFeedUpdater(threatFeedUpdater), eventBroadcaster(broadcaster), listenPort(port) {}

ApiServer::~ApiServer() { stop(); }

void ApiServer::start() {
    if (running) return;
    running = true;
    worker = std::thread(&ApiServer::run, this);
}

void ApiServer::stop() {
    if (!running) return;
    running = false;
    // connect to self to unblock accept
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock >= 0) {
        struct sockaddr_in sa{};
        sa.sin_family = AF_INET;
        sa.sin_port = htons(listenPort);
        sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        connect(sock, (struct sockaddr*)&sa, sizeof(sa));
        close(sock);
    }
    if (worker.joinable()) worker.join();

    std::lock_guard<std::mutex> lock(streamWorkersMutex);
    for (auto &streamWorker : streamWorkers) {
        if (streamWorker.joinable()) {
            streamWorker.join();
        }
    }
    streamWorkers.clear();
}

static std::string buildJsonForConnections(const std::vector<ConnectionRecord> &rows) {
    std::ostringstream ss;
    ss << "[";
    bool first = true;
    for (const auto &r : rows) {
        if (!first) ss << ",";
        first = false;
        ss << "{"
           << "\"id\":" << r.id << ","
           << "\"timestamp\":\"" << r.timestamp << "\"," 
           << "\"process_name\":\"" << r.process_name << "\"," 
           << "\"destination_ip\":\"" << r.destination_ip << "\"," 
           << "\"domain\":\"" << r.domain << "\"," 
           << "\"protocol\":\"" << r.protocol << "\"," 
           << "\"port\":" << r.port << ","
           << "\"bytes_sent\":" << r.bytes_sent << ","
           << "\"bytes_received\":" << r.bytes_received << ","
           << "\"action\":\"" << r.action << "\""
           << "}";
    }
    ss << "]";
    return ss.str();
}

static std::string buildJsonForDNS(const std::vector<DNSRecord> &rows) {
    std::ostringstream ss;
    ss << "[";
    bool first = true;
    for (const auto &r : rows) {
        if (!first) ss << ",";
        first = false;
        ss << "{"
           << "\"id\":" << r.id << ","
           << "\"timestamp\":\"" << r.timestamp << "\"," 
           << "\"src_ip\":\"" << r.src_ip << "\"," 
           << "\"query_name\":\"" << r.query_name << "\"," 
           << "\"query_type\":\"" << r.query_type << "\"," 
           << "\"process_name\":\"" << r.process_name << "\""
           << "}";
    }
    ss << "]";
    return ss.str();
}

void ApiServer::run() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        std::cerr << "ApiServer: socket failed\n";
        return;
    }

    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(listenPort);

    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        std::cerr << "ApiServer: bind failed\n";
        close(server_fd);
        return;
    }

    if (listen(server_fd, 128) < 0) {
        std::cerr << "ApiServer: listen failed\n";
        close(server_fd);
        return;
    }

    std::cout << "ApiServer: listening on port " << listenPort << std::endl;

    while (running) {
        struct sockaddr_in client_addr{};
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) {
            if (!running) break;
            continue;
        }
#ifdef SO_NOSIGPIPE
        int noSigpipe = 1;
        setsockopt(client_fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigpipe, sizeof(noSigpipe));
#endif

        // read request (very minimal)
        char buffer[4096];
        ssize_t n = recv(client_fd, buffer, sizeof(buffer)-1, 0);
        if (n <= 0) { close(client_fd); continue; }
        buffer[n] = '\0';
        std::string req(buffer);

        if (req.find("OPTIONS") == 0) {
            std::ostringstream resp;
            resp << "HTTP/1.1 204 No Content\r\n"
                 << "Access-Control-Allow-Origin: *\r\n"
                 << "Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS\r\n"
                 << "Access-Control-Allow-Headers: Content-Type, Accept, Authorization\r\n"
                 << "Access-Control-Max-Age: 86400\r\n"
                 << "Connection: close\r\n\r\n";
            std::string out = resp.str();
            send(client_fd, out.c_str(), out.size(), 0);
            close(client_fd);
            continue;
        }

        if (req.find("GET /api/stream") == 0) {
            if (eventBroadcaster == nullptr) {
                const char *notfound = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                send(client_fd, notfound, strlen(notfound), 0);
                close(client_fd);
                continue;
            }

            const std::uint64_t lastEventId = parseEventId(req);

            {
                std::lock_guard<std::mutex> lock(streamWorkersMutex);
                streamWorkers.emplace_back(&ApiServer::handleStreamClient, this, client_fd, lastEventId);
            }
            continue;
        } else if (req.find("GET /api/events") == 0) {
            const std::string domainFilter = getQueryParam(req, "domain");
            auto rows = database->getTrafficEvents(100, domainFilter);
            std::string body = buildJsonForTrafficEvents(rows);
            std::ostringstream resp;
            resp << "HTTP/1.1 200 OK\r\n";
            resp << "Content-Type: application/json\r\n";
            resp << "Content-Length: " << body.size() << "\r\n";
            resp << "Connection: close\r\n\r\n";
            resp << body;
            std::string out = resp.str();
            send(client_fd, out.c_str(), out.size(), 0);
        } else if (req.find("GET /api/stats") == 0) {
            TrafficStats stats = database->getTrafficStats();
            std::string body = buildJsonForStats(stats);
            std::ostringstream resp;
            resp << "HTTP/1.1 200 OK\r\n";
            resp << "Content-Type: application/json\r\n";
            resp << "Content-Length: " << body.size() << "\r\n";
            resp << "Connection: close\r\n\r\n";
            resp << body;
            std::string out = resp.str();
            send(client_fd, out.c_str(), out.size(), 0);
        } else if (req.find("GET /api/domains") == 0) {
            auto rows = database->getTopDomains(100);
            std::string body = buildJsonForDomainFrequency(rows);
            std::ostringstream resp;
            resp << "HTTP/1.1 200 OK\r\n";
            resp << "Content-Type: application/json\r\n";
            resp << "Content-Length: " << body.size() << "\r\n";
            resp << "Connection: close\r\n\r\n";
            resp << body;
            std::string out = resp.str();
            send(client_fd, out.c_str(), out.size(), 0);
        } else if (req.find("GET /api/blocked-events") == 0) {
            auto rows = database->getBlockedEvents(100);
            std::string body = buildJsonForBlockedEvents(rows);
            std::ostringstream resp;
            resp << "HTTP/1.1 200 OK\r\n";
            resp << "Content-Type: application/json\r\n";
            resp << "Content-Length: " << body.size() << "\r\n";
            resp << "Connection: close\r\n\r\n";
            resp << body;
            std::string out = resp.str();
            send(client_fd, out.c_str(), out.size(), 0);
        } else if (req.find("GET /api/block-stats") == 0) {
            BlockedStats stats = database->getBlockedStats();
            std::string body = buildJsonForBlockedStats(stats);
            std::ostringstream resp;
            resp << "HTTP/1.1 200 OK\r\n";
            resp << "Content-Type: application/json\r\n";
            resp << "Content-Length: " << body.size() << "\r\n";
            resp << "Connection: close\r\n\r\n";
            resp << body;
            std::string out = resp.str();
            send(client_fd, out.c_str(), out.size(), 0);
        } else if (req.find("GET /api/blocked-domains") == 0) {
            const std::vector<std::string> rules = policyEngine != nullptr ? policyEngine->getBlockedRules() : std::vector<std::string>{};
            std::string body = buildJsonForStringArray(rules);
            std::ostringstream resp;
            resp << "HTTP/1.1 200 OK\r\n";
            resp << "Content-Type: application/json\r\n";
            resp << "Content-Length: " << body.size() << "\r\n";
            resp << "Connection: close\r\n\r\n";
            resp << body;
            std::string out = resp.str();
            send(client_fd, out.c_str(), out.size(), 0);
        } else if (req.find("GET /api/threats") == 0) {
            const std::vector<ThreatIndicator> rows = threatIntel != nullptr ? threatIntel->getIndicators() : std::vector<ThreatIndicator>{};
            std::string body = buildJsonForThreatIndicators(rows);
            std::ostringstream resp;
            resp << "HTTP/1.1 200 OK\r\n";
            resp << "Content-Type: application/json\r\n";
            resp << "Content-Length: " << body.size() << "\r\n";
            resp << "Connection: close\r\n\r\n";
            resp << body;
            std::string out = resp.str();
            send(client_fd, out.c_str(), out.size(), 0);
        } else if (req.find("GET /api/threat-events") == 0) {
            auto rows = database->getThreatEvents(100);
            std::string body = buildJsonForThreatEvents(rows);
            std::ostringstream resp;
            resp << "HTTP/1.1 200 OK\r\n";
            resp << "Content-Type: application/json\r\n";
            resp << "Content-Length: " << body.size() << "\r\n";
            resp << "Connection: close\r\n\r\n";
            resp << body;
            std::string out = resp.str();
            send(client_fd, out.c_str(), out.size(), 0);
        } else if (req.find("GET /api/threat-stats") == 0) {
            ThreatStats stats = database->getThreatStats();
            std::string body = buildJsonForThreatStats(stats);
            std::ostringstream resp;
            resp << "HTTP/1.1 200 OK\r\n";
            resp << "Content-Type: application/json\r\n";
            resp << "Content-Length: " << body.size() << "\r\n";
            resp << "Connection: close\r\n\r\n";
            resp << body;
            std::string out = resp.str();
            send(client_fd, out.c_str(), out.size(), 0);
        } else if (req.find("GET /api/security/overview") == 0) {
            const SecurityOverviewRecord overview = database->getSecurityOverview();
            std::string body = buildJsonForSecurityOverview(overview);
            std::ostringstream resp;
            resp << "HTTP/1.1 200 OK\r\n";
            resp << "Content-Type: application/json\r\n";
            resp << "Content-Length: " << body.size() << "\r\n";
            resp << "Connection: close\r\n\r\n";
            resp << body;
            std::string out = resp.str();
            send(client_fd, out.c_str(), out.size(), 0);
        } else if (req.find("GET /api/security/incidents") == 0 || req.find("GET /api/security/analysis") == 0) {
            const auto rows = database->getSecurityAnalyses(100);
            std::string body = buildJsonForSecurityAnalyses(rows);
            std::ostringstream resp;
            resp << "HTTP/1.1 200 OK\r\n";
            resp << "Content-Type: application/json\r\n";
            resp << "Content-Length: " << body.size() << "\r\n";
            resp << "Connection: close\r\n\r\n";
            resp << body;
            std::string out = resp.str();
            send(client_fd, out.c_str(), out.size(), 0);
        } else if (req.find("GET /api/security/score") == 0) {
            const SecurityOverviewRecord overview = database->getSecurityOverview();
            std::ostringstream body;
            body << "{"
                 << "\"score\":" << overview.latest_score << ","
                 << "\"average_score\":" << overview.average_score << ","
                 << "\"severity\":\"" << (overview.latest_score >= 80 ? "Critical" : overview.latest_score >= 60 ? "High" : overview.latest_score >= 35 ? "Medium" : "Low") << "\""
                 << "}";
            std::ostringstream resp;
            resp << "HTTP/1.1 200 OK\r\n";
            resp << "Content-Type: application/json\r\n";
            resp << "Content-Length: " << body.str().size() << "\r\n";
            resp << "Connection: close\r\n\r\n";
            resp << body.str();
            std::string out = resp.str();
            send(client_fd, out.c_str(), out.size(), 0);
        } else if (req.find("GET /api/threat-feeds") == 0) {
            const auto feeds = database->getThreatFeedStatuses(100);
            const auto updates = database->getThreatFeedUpdates(100);
            const int intervalSeconds = threatFeedUpdater != nullptr ? threatFeedUpdater->getIntervalSeconds() : 0;
            const int threatCount = threatIntel != nullptr ? static_cast<int>(threatIntel->getIndicators().size()) : 0;
            std::string body = buildJsonForFeedSources(feeds, updates, intervalSeconds, threatCount);
            std::ostringstream resp;
            resp << "HTTP/1.1 200 OK\r\n";
            resp << "Content-Type: application/json\r\n";
            resp << "Content-Length: " << body.size() << "\r\n";
            resp << "Connection: close\r\n\r\n";
            resp << body;
            std::string out = resp.str();
            send(client_fd, out.c_str(), out.size(), 0);
        } else if (req.find("/api/threat-feeds/refresh") != std::string::npos) {
            ThreatFeedUpdateResult result;
            if (threatFeedUpdater != nullptr) {
                result = threatFeedUpdater->refreshNow();
            } else {
                result.timestamp = currentUtcTimestamp();
                result.message = "Threat feed updater is disabled";
            }
            std::ostringstream body;
            body << "{"
                 << "\"ok\":" << (result.ok ? "true" : "false") << ","
                 << "\"timestamp\":\"" << escapeJson(result.timestamp) << "\","
                 << "\"message\":\"" << escapeJson(result.message) << "\","
                 << "\"sources_checked\":" << result.sources_checked << ","
                 << "\"indicators_loaded\":" << result.indicators_loaded << ","
                 << "\"indicators_written\":" << result.indicators_written
                 << "}";
            std::ostringstream resp;
            resp << "HTTP/1.1 " << (result.ok ? "200 OK" : "500 Internal Server Error") << "\r\n";
            resp << "Content-Type: application/json\r\n";
            resp << "Access-Control-Allow-Origin: *\r\n";
            resp << "Content-Length: " << body.str().size() << "\r\n";
            resp << "Connection: close\r\n\r\n";
            resp << body.str();
            std::string out = resp.str();
            send(client_fd, out.c_str(), out.size(), 0);
        } else if (req.find("GET /api/firewall/status") == 0) {
            FirewallStatus status = firewallManager != nullptr ? firewallManager->getStatus() : FirewallStatus{};
            std::ostringstream body;
            body << "{";
            body << "\"backend\":\"" << escapeJson(status.backend) << "\",";
            body << "\"health\":\"" << escapeJson(status.health) << "\",";
            body << "\"active_rules\":" << status.activeRules << ",";
            body << "\"last_action\":\"" << escapeJson(status.lastAction) << "\",";
            body << "\"last_domain\":\"" << escapeJson(status.lastDomain) << "\",";
            body << "\"last_status\":\"" << escapeJson(status.lastStatus) << "\"";
            body << "}";
            std::ostringstream resp;
            resp << "HTTP/1.1 200 OK\r\n";
            resp << "Content-Type: application/json\r\n";
            resp << "Content-Length: " << body.str().size() << "\r\n";
            resp << "Connection: close\r\n\r\n";
            resp << body.str();
            std::string out = resp.str();
            send(client_fd, out.c_str(), out.size(), 0);
        } else if (req.find("GET /api/firewall/rules") == 0) {
            const std::vector<std::string> rules = firewallManager != nullptr ? firewallManager->getActiveRules() : std::vector<std::string>{};
            std::string body = buildJsonForStringArray(rules);
            std::ostringstream resp;
            resp << "HTTP/1.1 200 OK\r\n";
            resp << "Content-Type: application/json\r\n";
            resp << "Content-Length: " << body.size() << "\r\n";
            resp << "Connection: close\r\n\r\n";
            resp << body;
            std::string out = resp.str();
            send(client_fd, out.c_str(), out.size(), 0);
        } else if (req.find("GET /api/firewall/actions") == 0) {
            const std::vector<FirewallAction> rows = database->getFirewallActions(100);
            std::string body = buildJsonForFirewallActions(rows);
            std::ostringstream resp;
            resp << "HTTP/1.1 200 OK\r\n";
            resp << "Content-Type: application/json\r\n";
            resp << "Content-Length: " << body.size() << "\r\n";
            resp << "Connection: close\r\n\r\n";
            resp << body;
            std::string out = resp.str();
            send(client_fd, out.c_str(), out.size(), 0);
        } else if (req.find("POST /api/firewall/block") == 0) {
            const std::string domain = extractHost(urlDecode(getQueryParam(req, "domain")));
            const std::string timestamp = currentUtcTimestamp();
            const bool ok = firewallManager != nullptr && firewallManager->blockDomain(domain, "MANUAL", "", "", timestamp, "Manual firewall block");
            const char *body = ok ? "{\"ok\":true}" : "{\"ok\":false}";
            std::ostringstream resp;
            resp << "HTTP/1.1 " << (ok ? "200 OK" : "500 Internal Server Error") << "\r\n";
            resp << "Content-Type: application/json\r\n";
            resp << "Content-Length: " << std::strlen(body) << "\r\n";
            resp << "Connection: close\r\n\r\n";
            resp << body;
            std::string out = resp.str();
            send(client_fd, out.c_str(), out.size(), 0);
        } else if (req.find("POST /api/firewall/unblock") == 0 || req.find("DELETE /api/firewall/rule") == 0) {
            const std::string domain = extractHost(urlDecode(getQueryParam(req, "domain")));
            const std::string timestamp = currentUtcTimestamp();
            const bool ok = firewallManager != nullptr && firewallManager->unblockDomain(domain, timestamp, "Manual firewall unblock");
            const char *body = ok ? "{\"ok\":true}" : "{\"ok\":false}";
            std::ostringstream resp;
            resp << "HTTP/1.1 " << (ok ? "200 OK" : "500 Internal Server Error") << "\r\n";
            resp << "Content-Type: application/json\r\n";
            resp << "Content-Length: " << std::strlen(body) << "\r\n";
            resp << "Connection: close\r\n\r\n";
            resp << body;
            std::string out = resp.str();
            send(client_fd, out.c_str(), out.size(), 0);
        } else if (req.find("POST /api/firewall/clear") == 0) {
            const std::string timestamp = currentUtcTimestamp();
            const bool ok = firewallManager != nullptr && firewallManager->clearActiveRules(timestamp, "Manual firewall clear");
            const char *body = ok ? "{\"ok\":true}" : "{\"ok\":false}";
            std::ostringstream resp;
            resp << "HTTP/1.1 " << (ok ? "200 OK" : "500 Internal Server Error") << "\r\n";
            resp << "Content-Type: application/json\r\n";
            resp << "Content-Length: " << std::strlen(body) << "\r\n";
            resp << "Connection: close\r\n\r\n";
            resp << body;
            std::string out = resp.str();
            send(client_fd, out.c_str(), out.size(), 0);
        } else if (req.find("GET /api/policy-events") == 0) {
            auto rows = database->getPolicyEvents(100);
            std::string body = buildJsonForPolicyEvents(rows);
            std::ostringstream resp;
            resp << "HTTP/1.1 200 OK\r\n";
            resp << "Content-Type: application/json\r\n";
            resp << "Content-Length: " << body.size() << "\r\n";
            resp << "Connection: close\r\n\r\n";
            resp << body;
            std::string out = resp.str();
            send(client_fd, out.c_str(), out.size(), 0);
        } else if (req.find("GET /connections") == 0 || req.find("GET /api/connections") == 0) {
            auto rows = database->getConnections(100);
            std::string body = buildJsonForConnections(rows);
            std::ostringstream resp;
            resp << "HTTP/1.1 200 OK\r\n";
            resp << "Content-Type: application/json\r\n";
            resp << "Content-Length: " << body.size() << "\r\n";
            resp << "Connection: close\r\n\r\n";
            resp << body;
            std::string out = resp.str();
            send(client_fd, out.c_str(), out.size(), 0);
        } else if (req.find("GET /dns") == 0 || req.find("GET /api/dns") == 0) {
            auto rows = database->getDNSQueries(100);
            std::string body = buildJsonForDNS(rows);
            std::ostringstream resp;
            resp << "HTTP/1.1 200 OK\r\n";
            resp << "Content-Type: application/json\r\n";
            resp << "Content-Length: " << body.size() << "\r\n";
            resp << "Connection: close\r\n\r\n";
            resp << body;
            std::string out = resp.str();
            send(client_fd, out.c_str(), out.size(), 0);
        } else {
            const char *notfound = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            send(client_fd, notfound, strlen(notfound), 0);
        }

        close(client_fd);
    }

    close(server_fd);
    std::cout << "ApiServer: stopped" << std::endl;
}

void ApiServer::handleStreamClient(int clientFd, std::uint64_t lastEventId) {
    const std::string headers =
        "HTTP/1.1 200 OK\r\n"
        "Content-Type: text/event-stream\r\n"
        "Cache-Control: no-cache\r\n"
        "X-Accel-Buffering: no\r\n"
        "Connection: keep-alive\r\n"
        "Access-Control-Allow-Origin: *\r\n\r\n";

    if (send(clientFd, headers.c_str(), headers.size(), 0) < 0) {
        close(clientFd);
        return;
    }

    eventBroadcaster->addClient(clientFd, lastEventId);
    while (running) {
        const std::string heartbeat = ": keepalive\n\n";
        if (send(clientFd, heartbeat.c_str(), heartbeat.size(), 0) < 0) {
            break;
        }
        std::this_thread::sleep_for(std::chrono::seconds(15));
    }

    eventBroadcaster->removeClient(clientFd);
    close(clientFd);
}
