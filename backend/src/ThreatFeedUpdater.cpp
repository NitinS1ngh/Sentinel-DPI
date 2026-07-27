#include "ThreatFeedUpdater.h"
#include <algorithm>
#include <cctype>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <sstream>
#include <spawn.h>
#include <sys/wait.h>

extern char **environ;

namespace {
std::string currentUtcTimestamp() {
    std::time_t now = std::time(nullptr);
    std::tm tmUtc{};
#if defined(_WIN32)
    gmtime_s(&tmUtc, &now);
#else
    gmtime_r(&now, &tmUtc);
#endif
    char buffer[32];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &tmUtc);
    return buffer;
}

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

std::string trim(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return "";
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

std::string toLowerCopy(std::string value) {
    for (char &ch : value) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return value;
}

std::string normalizeDomain(std::string domain) {
    domain = toLowerCopy(trim(std::move(domain)));
    while (!domain.empty() && domain.front() == '.') domain.erase(domain.begin());
    while (!domain.empty() && domain.back() == '.') domain.pop_back();
    return domain;
}

bool startsWith(const std::string &value, const std::string &prefix) {
    return value.rfind(prefix, 0) == 0;
}

bool isRemoteUrl(const std::string &location) {
    return startsWith(location, "https://") || startsWith(location, "http://");
}

std::string sanitizeFileName(std::string value) {
    if (value.empty()) return "feed";
    for (char &ch : value) {
        const bool ok = std::isalnum(static_cast<unsigned char>(ch)) || ch == '-' || ch == '_';
        if (!ok) ch = '_';
    }
    return value;
}

std::string extractJsonStringField(const std::string &object, const std::string &field) {
    const std::string needle = '"' + field + '"';
    const auto fieldPos = object.find(needle);
    if (fieldPos == std::string::npos) return "";

    const auto colonPos = object.find(':', fieldPos + needle.size());
    if (colonPos == std::string::npos) return "";

    const auto firstQuote = object.find('"', colonPos + 1);
    if (firstQuote == std::string::npos) return "";

    std::string value;
    bool escaped = false;
    for (size_t i = firstQuote + 1; i < object.size(); ++i) {
        const char ch = object[i];
        if (escaped) {
            value.push_back(ch);
            escaped = false;
            continue;
        }
        if (ch == '\\') {
            escaped = true;
            continue;
        }
        if (ch == '"') {
            break;
        }
        value.push_back(ch);
    }
    return value;
}

bool extractJsonBoolField(const std::string &object, const std::string &field, bool defaultValue) {
    const std::string needle = '"' + field + '"';
    const auto fieldPos = object.find(needle);
    if (fieldPos == std::string::npos) return defaultValue;
    const auto colonPos = object.find(':', fieldPos + needle.size());
    if (colonPos == std::string::npos) return defaultValue;
    const auto start = object.find_first_not_of(" \t\r\n", colonPos + 1);
    if (start == std::string::npos) return defaultValue;
    if (object.compare(start, 4, "true") == 0) return true;
    if (object.compare(start, 5, "false") == 0) return false;
    return defaultValue;
}

std::vector<std::string> splitJsonObjects(const std::string &content) {
    std::vector<std::string> objects;
    int depth = 0;
    bool inString = false;
    bool escaped = false;
    size_t start = std::string::npos;

    for (size_t i = 0; i < content.size(); ++i) {
        const char ch = content[i];
        if (inString) {
            if (escaped) {
                escaped = false;
            } else if (ch == '\\') {
                escaped = true;
            } else if (ch == '"') {
                inString = false;
            }
            continue;
        }

        if (ch == '"') {
            inString = true;
        } else if (ch == '{') {
            if (depth == 0) start = i;
            ++depth;
        } else if (ch == '}') {
            --depth;
            if (depth == 0 && start != std::string::npos) {
                objects.push_back(content.substr(start, i - start + 1));
                start = std::string::npos;
            }
        }
    }

    return objects;
}

std::string extractJsonArrayField(const std::string &content, const std::string &field) {
    const std::string needle = '"' + field + '"';
    const auto fieldPos = content.find(needle);
    if (fieldPos == std::string::npos) return "";

    const auto arrayStart = content.find('[', fieldPos + needle.size());
    if (arrayStart == std::string::npos) return "";

    int depth = 0;
    bool inString = false;
    bool escaped = false;
    for (size_t i = arrayStart; i < content.size(); ++i) {
        const char ch = content[i];
        if (inString) {
            if (escaped) {
                escaped = false;
            } else if (ch == '\\') {
                escaped = true;
            } else if (ch == '"') {
                inString = false;
            }
            continue;
        }

        if (ch == '"') {
            inString = true;
        } else if (ch == '[') {
            ++depth;
        } else if (ch == ']') {
            --depth;
            if (depth == 0) {
                return content.substr(arrayStart, i - arrayStart + 1);
            }
        }
    }

    return "";
}

bool isBetterIndicator(const ThreatIndicator &lhs, const ThreatIndicator &rhs) {
    if (lhs.domain != rhs.domain) return lhs.domain < rhs.domain;
    if (lhs.category != rhs.category) return lhs.category < rhs.category;
    if (lhs.severity != rhs.severity) return lhs.severity < rhs.severity;
    return lhs.description < rhs.description;
}

std::string serializeIndicators(const std::vector<ThreatIndicator> &indicators) {
    std::ostringstream ss;
    ss << "[\n";
    for (size_t i = 0; i < indicators.size(); ++i) {
        const auto &indicator = indicators[i];
        ss << "  {\n"
           << "    \"domain\": \"" << escapeJson(indicator.domain) << "\",\n"
           << "    \"category\": \"" << escapeJson(indicator.category) << "\",\n"
           << "    \"severity\": \"" << escapeJson(indicator.severity) << "\",\n"
           << "    \"description\": \"" << escapeJson(indicator.description) << "\"\n"
           << "  }";
        if (i + 1 < indicators.size()) ss << ",";
        ss << "\n";
    }
    ss << "]\n";
    return ss.str();
}

std::string addSecondsToTimestamp(const std::string &timestamp, int seconds) {
    std::tm tmUtc{};
    std::istringstream ss(timestamp);
    ss >> std::get_time(&tmUtc, "%Y-%m-%d %H:%M:%S");
    if (ss.fail()) return "";

#if defined(_WIN32)
    const std::time_t base = _mkgmtime(&tmUtc);
#else
    const std::time_t base = timegm(&tmUtc);
#endif
    if (base == static_cast<std::time_t>(-1)) return "";

    std::time_t next = base + seconds;
    std::tm nextUtc{};
#if defined(_WIN32)
    gmtime_s(&nextUtc, &next);
#else
    gmtime_r(&next, &nextUtc);
#endif
    char buffer[32];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", &nextUtc);
    return buffer;
}
} // namespace

ThreatFeedUpdater::ThreatFeedUpdater(Database *database,
                                     ThreatIntelEngine *threatIntel,
                                     EventBroadcaster *eventBroadcaster,
                                     const std::string &registryPath,
                                     const std::string &outputPath,
                                     int intervalSeconds)
    : database(database), threatIntel(threatIntel), eventBroadcaster(eventBroadcaster), registryPath(registryPath), outputPath(outputPath), intervalSeconds(intervalSeconds) {}

ThreatFeedUpdater::~ThreatFeedUpdater() { stop(); }

void ThreatFeedUpdater::start() {
    if (running) return;
    running = true;
    worker = std::thread(&ThreatFeedUpdater::run, this);
}

void ThreatFeedUpdater::stop() {
    if (!running) return;
    running = false;
    if (worker.joinable()) worker.join();
}

ThreatFeedUpdateResult ThreatFeedUpdater::refreshNow() { return performRefresh(); }

std::vector<ThreatFeedSource> ThreatFeedUpdater::getSources() const { return sourcesCache; }

int ThreatFeedUpdater::getIntervalSeconds() const { return intervalSeconds; }

void ThreatFeedUpdater::run() {
    performRefresh();
    while (running) {
        const int waitSeconds = std::max(30, intervalSeconds);
        for (int elapsed = 0; running && elapsed < waitSeconds; elapsed += 1) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        if (!running) {
            break;
        }
        performRefresh();
    }
}

bool ThreatFeedUpdater::loadRegistry(std::vector<ThreatFeedSource> &out, std::string &error) const {
    std::ifstream input(registryPath);
    if (!input.is_open()) {
        error = "Could not open feed registry";
        return false;
    }

    const std::string content((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    const std::string feedsArray = extractJsonArrayField(content, "feeds");
    const std::string sourceContent = feedsArray.empty() ? content : feedsArray;
    for (const auto &object : splitJsonObjects(sourceContent)) {
        ThreatFeedSource source;
        source.name = extractJsonStringField(object, "name");
        source.path = extractJsonStringField(object, "path");
        source.type = extractJsonStringField(object, "type");
        source.url = extractJsonStringField(object, "url");
        source.version = extractJsonStringField(object, "version");
        source.enabled = extractJsonBoolField(object, "enabled", true);
        if (source.name.empty()) source.name = source.path.empty() ? source.url : source.path;
        if (source.type.empty()) source.type = "json";
        if (source.version.empty()) source.version = "local";
        if (!source.path.empty() || !source.url.empty()) {
            out.push_back(source);
        }
    }

    if (out.empty()) {
        error = "No feed sources found";
        return false;
    }

    return true;
}

bool ThreatFeedUpdater::loadIndicatorsFile(const std::string &path, std::vector<ThreatIndicator> &out, std::string &error) const {
    std::ifstream input(path);
    if (!input.is_open()) {
        error = "Could not open feed source: " + path;
        return false;
    }

    const std::string content((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    for (const auto &object : splitJsonObjects(content)) {
        ThreatIndicator indicator;
        indicator.domain = normalizeDomain(extractJsonStringField(object, "domain"));
        indicator.category = extractJsonStringField(object, "category");
        indicator.severity = extractJsonStringField(object, "severity");
        indicator.description = extractJsonStringField(object, "description");
        if (!indicator.domain.empty()) {
            out.push_back(indicator);
        }
    }

    return true;
}

bool ThreatFeedUpdater::loadDomainListFile(const std::string &path, std::vector<ThreatIndicator> &out, const ThreatFeedSource &source, std::string &error) const {
    std::ifstream input(path);
    if (!input.is_open()) {
        error = "Could not open feed source: " + path;
        return false;
    }

    std::string line;
    while (std::getline(input, line)) {
        const auto comment = line.find('#');
        if (comment != std::string::npos) {
            line = line.substr(0, comment);
        }

        line = trim(line);
        if (line.empty()) continue;

        std::istringstream iss(line);
        std::vector<std::string> tokens;
        std::string token;
        while (iss >> token) {
            tokens.push_back(token);
        }

        if (tokens.empty()) continue;

        std::string rawDomain;
        if (tokens.size() == 1) {
            rawDomain = tokens[0];
        } else if (tokens.size() >= 2) {
            const std::string &t0 = tokens[0];
            if (t0 == "127.0.0.1" || t0 == "0.0.0.0" || t0 == "::1" || t0.find('.') != std::string::npos) {
                rawDomain = tokens[1];
            } else {
                rawDomain = tokens[0];
            }
        }

        const std::string domain = normalizeDomain(rawDomain);
        if (domain.empty()) continue;
        if (domain == "localhost" || domain == "broadcasthost" || domain == "local" || domain == "localhost.localdomain") continue;

        ThreatIndicator indicator;
        indicator.domain = domain;
        indicator.category = source.name.empty() ? "Threat Feed" : source.name;
        indicator.severity = "High";
        indicator.description = "Listed by " + source.name;
        out.push_back(indicator);
    }

    return true;
}

bool ThreatFeedUpdater::downloadToFile(const std::string &url, const std::string &path, std::string &error) const {
    if (!isRemoteUrl(url)) {
        error = "Unsupported feed URL: " + url;
        return false;
    }

    char *argv[] = {
        const_cast<char*>("curl"),
        const_cast<char*>("-fsSL"),
        const_cast<char*>("--max-time"),
        const_cast<char*>("30"),
        const_cast<char*>("-o"),
        const_cast<char*>(path.c_str()),
        const_cast<char*>(url.c_str()),
        nullptr
    };

    pid_t pid = 0;
    const int spawnResult = posix_spawnp(&pid, "curl", nullptr, nullptr, argv, environ);
    if (spawnResult != 0) {
        error = "Could not start curl for feed download";
        return false;
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        error = "Could not wait for feed download";
        return false;
    }

    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        error = "Feed download failed: " + url;
        return false;
    }

    return true;
}

bool ThreatFeedUpdater::loadIndicatorsFromSource(const ThreatFeedSource &source, std::vector<ThreatIndicator> &out, std::string &error) const {
    std::string path = source.path;
    if (!source.url.empty()) {
        try {
            std::filesystem::create_directories(".sentinel-feeds");
            path = (std::filesystem::path(".sentinel-feeds") / (sanitizeFileName(source.name) + ".download")).string();
        } catch (const std::exception &ex) {
            error = std::string("Could not create feed cache directory: ") + ex.what();
            return false;
        }

        if (!downloadToFile(source.url, path, error)) {
            return false;
        }
    }

    const std::string type = toLowerCopy(source.type);
    if (type == "domain-list" || type == "text" || type == "hostfile") {
        return loadDomainListFile(path, out, source, error);
    }

    return loadIndicatorsFile(path, out, error);
}

bool ThreatFeedUpdater::writeIndicatorsFile(const std::vector<ThreatIndicator> &indicators, std::string &error) const {
    std::ofstream output(outputPath, std::ios::trunc);
    if (!output.is_open()) {
        error = "Could not write threat feed output";
        return false;
    }

    output << serializeIndicators(indicators);
    return true;
}

ThreatFeedUpdateResult ThreatFeedUpdater::performRefresh() {
    ThreatFeedUpdateResult result;
    result.timestamp = currentUtcTimestamp();

    std::vector<ThreatFeedSource> sources;
    std::string error;
    if (!loadRegistry(sources, error)) {
        result.message = error;
        return result;
    }

    sourcesCache = sources;
    result.sources_checked = static_cast<int>(sources.size());

    std::vector<ThreatIndicator> merged;
    int failedSources = 0;
    for (const auto &source : sources) {
        const std::string location = source.url.empty() ? source.path : source.url;
        if (!source.enabled) {
            if (database != nullptr) {
                database->upsertThreatFeedStatus({0, source.name, source.type, location, "DISABLED", "", "", 0, source.version, "Disabled", ""});
            }
            continue;
        }

        std::vector<ThreatIndicator> indicators;
        if (!loadIndicatorsFromSource(source, indicators, error)) {
            result.message = error;
            ++failedSources;
            if (database != nullptr) {
                database->upsertThreatFeedStatus({0, source.name, source.type, location, "FAILED", result.timestamp, addSecondsToTimestamp(result.timestamp, intervalSeconds), 0, source.version, "Degraded", error});
            }
            continue;
        }

        result.indicators_loaded += static_cast<int>(indicators.size());
        if (database != nullptr) {
            database->upsertThreatFeedStatus({0, source.name, source.type, location, "REFRESHED", result.timestamp, addSecondsToTimestamp(result.timestamp, intervalSeconds), static_cast<int>(indicators.size()), source.version, "Healthy", ""});
        }
        merged.insert(merged.end(), indicators.begin(), indicators.end());
    }

    if (merged.empty()) {
        if (result.message.empty()) {
            result.message = "No indicators loaded from configured feeds";
        }
        if (database != nullptr) {
            database->insertThreatFeedUpdate({0, result.timestamp, "registry", "FAILED", result.sources_checked, 0, result.message});
        }
        return result;
    }

    std::sort(merged.begin(), merged.end(), isBetterIndicator);
    merged.erase(std::unique(merged.begin(), merged.end(), [](const ThreatIndicator &lhs, const ThreatIndicator &rhs) {
        return lhs.domain == rhs.domain && lhs.category == rhs.category && lhs.severity == rhs.severity && lhs.description == rhs.description;
    }), merged.end());

    if (!writeIndicatorsFile(merged, error)) {
        result.message = error;
        return result;
    }

    result.ok = true;
    result.indicators_written = static_cast<int>(merged.size());
    result.message = failedSources > 0 ? "Threat feeds refreshed with source errors" : "Threat feeds refreshed";

    if (database != nullptr) {
        database->insertThreatFeedUpdate({0, result.timestamp, "registry", "REFRESHED", result.sources_checked, result.indicators_written, result.message});
    }

    if (threatIntel != nullptr) {
        threatIntel->refresh();
    }

    if (eventBroadcaster != nullptr) {
        std::ostringstream payload;
        payload << "{" << "\"type\":\"SECURITY_FEEDS\"," << "\"timestamp\":\"" << escapeJson(result.timestamp) << "\"," << "\"message\":\"" << escapeJson(result.message) << "\"," << "\"sources_checked\":" << result.sources_checked << "," << "\"indicators_written\":" << result.indicators_written << "}";
        eventBroadcaster->broadcast(payload.str());
    }

    return result;
}
