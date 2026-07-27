#include "Database.h"
#include <algorithm>
#include <ctime>
#include <iostream>
#include <sstream>

namespace {
std::string escapeLike(const std::string &value) {
  std::string escaped;
  escaped.reserve(value.size());
  for (char ch : value) {
    if (ch == '\\' || ch == '%' || ch == '_') {
      escaped.push_back('\\');
    }
    escaped.push_back(ch);
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

std::string currentUtcDatePrefix() {
  const std::string timestamp = currentUtcTimestamp();
  return timestamp.substr(0, 10);
}

bool columnExists(sqlite3 *db, const char *tableName, const char *columnName) {
  std::string sql = std::string("PRAGMA table_info(") + tableName + ");";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
    return false;
  }

  bool exists = false;
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    const char *name =
        reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
    if (name != nullptr && std::string(name) == columnName) {
      exists = true;
      break;
    }
  }

  sqlite3_finalize(stmt);
  return exists;
}

bool addColumnIfMissing(sqlite3 *db, const char *tableName,
                        const char *columnSql) {
  char *err = nullptr;
  const std::string sql = std::string("ALTER TABLE ") + tableName +
                          " ADD COLUMN " + columnSql + ";";
  if (sqlite3_exec(db, sql.c_str(), nullptr, nullptr, &err) == SQLITE_OK) {
    return true;
  }

  if (err != nullptr) {
    const std::string message = err;
    sqlite3_free(err);
    if (message.find("duplicate column name") != std::string::npos) {
      return true;
    }
  }

  return false;
}

std::string columnText(sqlite3_stmt *stmt, int column) {
  const auto *text = sqlite3_column_text(stmt, column);
  return text == nullptr ? "" : reinterpret_cast<const char *>(text);
}
} // namespace

Database::Database(const std::string &path) : dbPath(path) {}

Database::~Database() { close(); }

bool Database::open() {
  std::lock_guard<std::recursive_mutex> lock(dbMutex);
  if (sqlite3_open(dbPath.c_str(), &db) != SQLITE_OK) {
    std::cerr << "Cannot open database: " << sqlite3_errmsg(db) << "\n";
    db = nullptr;
    return false;
  }
  return true;
}

void Database::close() {
  std::lock_guard<std::recursive_mutex> lock(dbMutex);
  if (db) {
    sqlite3_close(db);
    db = nullptr;
  }
}

bool Database::initializeSchema() {
  std::lock_guard<std::recursive_mutex> lock(dbMutex);
  const char *sql = R"SQL(
    CREATE TABLE IF NOT EXISTS connections (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        process_name TEXT,
        destination_ip TEXT,
        domain TEXT,
        protocol TEXT,
        port INTEGER,
        bytes_sent INTEGER,
        bytes_received INTEGER,
        action TEXT
    );

    CREATE TABLE IF NOT EXISTS blocked_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        domain TEXT,
        protocol TEXT,
        source_ip TEXT,
        destination_ip TEXT,
        reason TEXT
    );

    CREATE TABLE IF NOT EXISTS vpn_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        vpn_type TEXT,
        destination TEXT
    );

    CREATE TABLE IF NOT EXISTS threat_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        domain TEXT,
        category TEXT,
        severity TEXT,
        description TEXT,
        protocol TEXT,
        source_ip TEXT,
        destination_ip TEXT,
        reason TEXT
    );

    CREATE TABLE IF NOT EXISTS policies (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        category TEXT,
        action TEXT
    );

    CREATE TABLE IF NOT EXISTS dns_queries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        src_ip TEXT,
        query_name TEXT,
        query_type TEXT,
        process_name TEXT
    );

    CREATE TABLE IF NOT EXISTS traffic_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        event_type TEXT,
        domain TEXT,
        source_ip TEXT,
        destination_ip TEXT,
        protocol TEXT
    );

    CREATE TABLE IF NOT EXISTS policy_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        domain TEXT,
        policy_type TEXT,
        source_ip TEXT
    );

    CREATE TABLE IF NOT EXISTS firewall_actions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        domain TEXT,
        action TEXT,
        backend TEXT,
        status TEXT,
        reason TEXT
    );

    CREATE TABLE IF NOT EXISTS security_analysis (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        domain TEXT,
        source_ip TEXT,
        destination_ip TEXT,
        protocol TEXT,
        event_type TEXT,
        category TEXT,
        severity TEXT,
        confidence TEXT,
        score INTEGER,
        explanation TEXT,
        recommendation TEXT
    );

    CREATE TABLE IF NOT EXISTS threat_feed_updates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        source TEXT,
        status TEXT,
        sources_checked INTEGER,
        indicators_loaded INTEGER,
        message TEXT
    );

    CREATE TABLE IF NOT EXISTS threat_feeds (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE,
        type TEXT,
        location TEXT,
        status TEXT,
        last_update TEXT,
        next_update TEXT,
        threat_count INTEGER,
        version TEXT,
        health TEXT,
        error TEXT
    );

    CREATE INDEX IF NOT EXISTS idx_traffic_events_domain ON traffic_events(domain);
    CREATE INDEX IF NOT EXISTS idx_traffic_events_timestamp ON traffic_events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_policy_events_timestamp ON policy_events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_policy_events_domain ON policy_events(domain);
    CREATE INDEX IF NOT EXISTS idx_blocked_events_timestamp ON blocked_events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_blocked_events_domain ON blocked_events(domain);
    CREATE INDEX IF NOT EXISTS idx_firewall_actions_timestamp ON firewall_actions(timestamp);
    CREATE INDEX IF NOT EXISTS idx_firewall_actions_domain ON firewall_actions(domain);
    CREATE INDEX IF NOT EXISTS idx_threat_events_timestamp ON threat_events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_threat_events_domain ON threat_events(domain);
    CREATE INDEX IF NOT EXISTS idx_threat_events_category ON threat_events(category);
    CREATE INDEX IF NOT EXISTS idx_threat_events_severity ON threat_events(severity);
    CREATE INDEX IF NOT EXISTS idx_security_analysis_timestamp ON security_analysis(timestamp);
    CREATE INDEX IF NOT EXISTS idx_security_analysis_domain ON security_analysis(domain);
    CREATE INDEX IF NOT EXISTS idx_security_analysis_severity ON security_analysis(severity);
    CREATE INDEX IF NOT EXISTS idx_security_analysis_score ON security_analysis(score);
    CREATE INDEX IF NOT EXISTS idx_threat_feed_updates_timestamp ON threat_feed_updates(timestamp);
    CREATE INDEX IF NOT EXISTS idx_threat_feeds_name ON threat_feeds(name);
    )SQL";

  char *err = nullptr;
  if (sqlite3_exec(db, sql, nullptr, nullptr, &err) != SQLITE_OK) {
    std::cerr << "Failed to initialize schema: " << (err ? err : "unknown")
              << "\n";
    if (err)
      sqlite3_free(err);
    return false;
  }

  addColumnIfMissing(db, "blocked_events", "protocol TEXT");
  addColumnIfMissing(db, "blocked_events", "source_ip TEXT");
  addColumnIfMissing(db, "blocked_events", "destination_ip TEXT");
  addColumnIfMissing(db, "threat_events", "category TEXT");
  addColumnIfMissing(db, "threat_events", "severity TEXT");
  addColumnIfMissing(db, "threat_events", "description TEXT");
  addColumnIfMissing(db, "threat_events", "protocol TEXT");
  addColumnIfMissing(db, "threat_events", "source_ip TEXT");
  addColumnIfMissing(db, "threat_events", "destination_ip TEXT");
  addColumnIfMissing(db, "threat_events", "reason TEXT");
  addColumnIfMissing(db, "security_analysis", "source_ip TEXT");
  addColumnIfMissing(db, "security_analysis", "destination_ip TEXT");
  addColumnIfMissing(db, "security_analysis", "protocol TEXT");
  addColumnIfMissing(db, "security_analysis", "event_type TEXT");
  addColumnIfMissing(db, "security_analysis", "category TEXT");
  addColumnIfMissing(db, "security_analysis", "severity TEXT");
  addColumnIfMissing(db, "security_analysis", "confidence TEXT");
  addColumnIfMissing(db, "security_analysis", "score INTEGER");
  addColumnIfMissing(db, "security_analysis", "explanation TEXT");
  addColumnIfMissing(db, "security_analysis", "recommendation TEXT");
  addColumnIfMissing(db, "threat_feed_updates", "source TEXT");
  addColumnIfMissing(db, "threat_feed_updates", "status TEXT");
  addColumnIfMissing(db, "threat_feed_updates", "sources_checked INTEGER");
  addColumnIfMissing(db, "threat_feed_updates", "indicators_loaded INTEGER");
  addColumnIfMissing(db, "threat_feed_updates", "message TEXT");
  addColumnIfMissing(db, "threat_feeds", "type TEXT");
  addColumnIfMissing(db, "threat_feeds", "location TEXT");
  addColumnIfMissing(db, "threat_feeds", "status TEXT");
  addColumnIfMissing(db, "threat_feeds", "last_update TEXT");
  addColumnIfMissing(db, "threat_feeds", "next_update TEXT");
  addColumnIfMissing(db, "threat_feeds", "threat_count INTEGER");
  addColumnIfMissing(db, "threat_feeds", "version TEXT");
  addColumnIfMissing(db, "threat_feeds", "health TEXT");
  addColumnIfMissing(db, "threat_feeds", "error TEXT");
  return true;
}

bool Database::insertConnection(const ConnectionRecord &rec) {
  std::lock_guard<std::recursive_mutex> lock(dbMutex);
  const char *sql =
      "INSERT INTO connections (timestamp, process_name, destination_ip, "
      "domain, protocol, port, bytes_sent, bytes_received, action) VALUES (?, "
      "?, ?, ?, ?, ?, ?, ?, ?);";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return false;

  sqlite3_bind_text(stmt, 1, rec.timestamp.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, rec.process_name.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 3, rec.destination_ip.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 4, rec.domain.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 5, rec.protocol.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 6, rec.port);
  sqlite3_bind_int64(stmt, 7, rec.bytes_sent);
  sqlite3_bind_int64(stmt, 8, rec.bytes_received);
  sqlite3_bind_text(stmt, 9, rec.action.c_str(), -1, SQLITE_TRANSIENT);

  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  sqlite3_finalize(stmt);
  return ok;
}

bool Database::insertDNSQuery(const DNSRecord &rec) {
  std::lock_guard<std::recursive_mutex> lock(dbMutex);
  const char *sql = "INSERT INTO dns_queries (timestamp, src_ip, query_name, "
                    "query_type, process_name) VALUES (?, ?, ?, ?, ?);";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return false;

  sqlite3_bind_text(stmt, 1, rec.timestamp.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, rec.src_ip.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 3, rec.query_name.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 4, rec.query_type.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 5, rec.process_name.c_str(), -1, SQLITE_TRANSIENT);

  bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  sqlite3_finalize(stmt);
  return ok;
}

bool Database::insertTrafficEvent(const TrafficEvent &rec) {
  std::lock_guard<std::recursive_mutex> lock(dbMutex);
  if (db == nullptr) {
    return false;
  }

  const char *dedupeSql = R"SQL(
        SELECT 1
        FROM traffic_events
        WHERE event_type = ?
          AND domain = ?
          AND source_ip = ?
          AND destination_ip = ?
          AND protocol = ?
          AND strftime('%s', timestamp) >= strftime('%s', ?) - 5
        ORDER BY timestamp DESC, id DESC
        LIMIT 1;
    )SQL";

  sqlite3_stmt *dedupeStmt = nullptr;
  if (sqlite3_prepare_v2(db, dedupeSql, -1, &dedupeStmt, nullptr) !=
      SQLITE_OK) {
    return false;
  }

  sqlite3_bind_text(dedupeStmt, 1, rec.event_type.c_str(), -1,
                    SQLITE_TRANSIENT);
  sqlite3_bind_text(dedupeStmt, 2, rec.domain.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(dedupeStmt, 3, rec.source_ip.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(dedupeStmt, 4, rec.destination_ip.c_str(), -1,
                    SQLITE_TRANSIENT);
  sqlite3_bind_text(dedupeStmt, 5, rec.protocol.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(dedupeStmt, 6, rec.timestamp.c_str(), -1, SQLITE_TRANSIENT);

  const bool duplicate = sqlite3_step(dedupeStmt) == SQLITE_ROW;
  sqlite3_finalize(dedupeStmt);
  if (duplicate) {
    return false;
  }

  const char *sql =
      "INSERT INTO traffic_events (timestamp, event_type, domain, source_ip, "
      "destination_ip, protocol) VALUES (?, ?, ?, ?, ?, ?);";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    return false;

  sqlite3_bind_text(stmt, 1, rec.timestamp.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, rec.event_type.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 3, rec.domain.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 4, rec.source_ip.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 5, rec.destination_ip.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 6, rec.protocol.c_str(), -1, SQLITE_TRANSIENT);

  const bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  sqlite3_finalize(stmt);
  return ok;
}

std::vector<TrafficEvent>
Database::getTrafficEvents(int limit, const std::string &domainFilter) {
  std::lock_guard<std::recursive_mutex> lock(dbMutex);
  std::vector<TrafficEvent> out;
  std::ostringstream sql;
  sql << "SELECT id, timestamp, event_type, domain, source_ip, destination_ip, "
         "protocol FROM traffic_events ";
  if (!domainFilter.empty()) {
    sql << "WHERE domain LIKE ? ESCAPE '\\' ";
  }
  sql << "ORDER BY timestamp DESC, id DESC LIMIT ?;";

  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql.str().c_str(), -1, &stmt, nullptr) !=
      SQLITE_OK) {
    return out;
  }

  int bindIndex = 1;
  if (!domainFilter.empty()) {
    const std::string pattern = "%" + escapeLike(domainFilter) + "%";
    sqlite3_bind_text(stmt, bindIndex++, pattern.c_str(), -1, SQLITE_TRANSIENT);
  }
  sqlite3_bind_int(stmt, bindIndex, limit);

  while (sqlite3_step(stmt) == SQLITE_ROW) {
    TrafficEvent rec;
    rec.id = sqlite3_column_int(stmt, 0);
    rec.timestamp = columnText(stmt, 1);
    rec.event_type = columnText(stmt, 2);
    rec.domain = columnText(stmt, 3);
    rec.source_ip = columnText(stmt, 4);
    rec.destination_ip = columnText(stmt, 5);
    rec.protocol = columnText(stmt, 6);
    out.push_back(rec);
  }

  sqlite3_finalize(stmt);
  return out;
}

TrafficStats Database::getTrafficStats() {
  std::lock_guard<std::recursive_mutex> lock(dbMutex);
  TrafficStats stats;
  if (db == nullptr) {
    return stats;
  }

  const char *countSql =
      "SELECT SUM(CASE WHEN event_type = 'DNS' THEN 1 ELSE 0 END), SUM(CASE "
      "WHEN event_type = 'TLS' THEN 1 ELSE 0 END) FROM traffic_events;";
  sqlite3_stmt *countStmt = nullptr;
  if (sqlite3_prepare_v2(db, countSql, -1, &countStmt, nullptr) == SQLITE_OK) {
    if (sqlite3_step(countStmt) == SQLITE_ROW) {
      stats.total_dns_events = sqlite3_column_int(countStmt, 0);
      stats.total_tls_events = sqlite3_column_int(countStmt, 1);
    }
  }
  sqlite3_finalize(countStmt);

  stats.top_domains = getTopDomains(10);
  return stats;
}

std::vector<DomainFrequency> Database::getTopDomains(int limit) {
  std::lock_guard<std::recursive_mutex> lock(dbMutex);
  std::vector<DomainFrequency> out;
  const char *sql =
      "SELECT domain, COUNT(*) AS count FROM traffic_events WHERE domain <> '' "
      "GROUP BY domain ORDER BY count DESC, domain ASC LIMIT ?;";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    return out;
  }

  sqlite3_bind_int(stmt, 1, limit);
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    DomainFrequency frequency;
    frequency.domain = columnText(stmt, 0);
    frequency.count = sqlite3_column_int(stmt, 1);
    out.push_back(frequency);
  }

  sqlite3_finalize(stmt);
  return out;
}

std::vector<DNSRecord> Database::getDNSQueries(int limit) {
  std::lock_guard<std::recursive_mutex> lock(dbMutex);
  std::vector<DNSRecord> out;
  std::string sql = "SELECT id, timestamp, src_ip, query_name, query_type, "
                    "process_name FROM dns_queries ORDER BY id DESC LIMIT " +
                    std::to_string(limit) + ";";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
    return out;

  while (sqlite3_step(stmt) == SQLITE_ROW) {
    DNSRecord r;
    r.id = sqlite3_column_int(stmt, 0);
    r.timestamp = columnText(stmt, 1);
    r.src_ip = columnText(stmt, 2);
    r.query_name = columnText(stmt, 3);
    r.query_type = columnText(stmt, 4);
    r.process_name = columnText(stmt, 5);
    out.push_back(r);
  }

  sqlite3_finalize(stmt);
  return out;
}

std::vector<ConnectionRecord> Database::getConnections(int limit) {
  std::lock_guard<std::recursive_mutex> lock(dbMutex);
  std::vector<ConnectionRecord> out;
  std::string sql = "SELECT id, timestamp, process_name, destination_ip, "
                    "domain, protocol, port, bytes_sent, bytes_received, "
                    "action FROM connections ORDER BY id DESC LIMIT " +
                    std::to_string(limit) + ";";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK)
    return out;

  while (sqlite3_step(stmt) == SQLITE_ROW) {
    ConnectionRecord r;
    r.id = sqlite3_column_int(stmt, 0);
    r.timestamp = columnText(stmt, 1);
    r.process_name = columnText(stmt, 2);
    r.destination_ip = columnText(stmt, 3);
    r.domain = columnText(stmt, 4);
    r.protocol = columnText(stmt, 5);
    r.port = sqlite3_column_int(stmt, 6);
    r.bytes_sent = sqlite3_column_int64(stmt, 7);
    r.bytes_received = sqlite3_column_int64(stmt, 8);
    r.action = columnText(stmt, 9);
    out.push_back(r);
  }

  sqlite3_finalize(stmt);
  return out;
}

bool Database::insertPolicyEvent(const PolicyEvent &rec) {
  std::lock_guard<std::recursive_mutex> lock(dbMutex);
  if (db == nullptr) {
    return false;
  }

  const char *dedupeSql = R"SQL(
        SELECT 1
        FROM policy_events
        WHERE domain = ?
          AND policy_type = ?
          AND source_ip = ?
          AND strftime('%s', timestamp) >= strftime('%s', ?) - 5
        ORDER BY timestamp DESC, id DESC
        LIMIT 1;
    )SQL";

  sqlite3_stmt *dedupeStmt = nullptr;
  if (sqlite3_prepare_v2(db, dedupeSql, -1, &dedupeStmt, nullptr) !=
      SQLITE_OK) {
    return false;
  }

  sqlite3_bind_text(dedupeStmt, 1, rec.domain.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(dedupeStmt, 2, rec.policy_type.c_str(), -1,
                    SQLITE_TRANSIENT);
  sqlite3_bind_text(dedupeStmt, 3, rec.source_ip.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(dedupeStmt, 4, rec.timestamp.c_str(), -1, SQLITE_TRANSIENT);

  const bool duplicate = sqlite3_step(dedupeStmt) == SQLITE_ROW;
  sqlite3_finalize(dedupeStmt);
  if (duplicate) {
    return false;
  }

  const char *sql = "INSERT INTO policy_events (timestamp, domain, "
                    "policy_type, source_ip) VALUES (?, ?, ?, ?);";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    return false;
  }

  sqlite3_bind_text(stmt, 1, rec.timestamp.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, rec.domain.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 3, rec.policy_type.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 4, rec.source_ip.c_str(), -1, SQLITE_TRANSIENT);

  const bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  sqlite3_finalize(stmt);
  return ok;
}

std::vector<PolicyEvent> Database::getPolicyEvents(int limit) {
  std::lock_guard<std::recursive_mutex> lock(dbMutex);
  std::vector<PolicyEvent> out;
  if (db == nullptr) {
    return out;
  }

  const char *sql = "SELECT id, timestamp, domain, policy_type, source_ip FROM "
                    "policy_events ORDER BY timestamp DESC, id DESC LIMIT ?;";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    return out;
  }

  sqlite3_bind_int(stmt, 1, limit);
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    PolicyEvent rec;
    rec.id = sqlite3_column_int(stmt, 0);
    rec.timestamp = columnText(stmt, 1);
    rec.domain = columnText(stmt, 2);
    rec.policy_type = columnText(stmt, 3);
    rec.source_ip = columnText(stmt, 4);
    out.push_back(rec);
  }

  sqlite3_finalize(stmt);
  return out;
}

bool Database::insertBlockedEvent(const BlockedEvent &rec) {
  std::lock_guard<std::recursive_mutex> lock(dbMutex);
  if (db == nullptr) {
    return false;
  }

  const char *sql =
      "INSERT INTO blocked_events (timestamp, domain, protocol, source_ip, "
      "destination_ip, reason) VALUES (?, ?, ?, ?, ?, ?);";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    return false;
  }

  sqlite3_bind_text(stmt, 1, rec.timestamp.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, rec.domain.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 3, rec.protocol.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 4, rec.source_ip.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 5, rec.destination_ip.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 6, rec.reason.c_str(), -1, SQLITE_TRANSIENT);

  const bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  sqlite3_finalize(stmt);
  return ok;
}

std::vector<BlockedEvent> Database::getBlockedEvents(int limit) {
  std::lock_guard<std::recursive_mutex> lock(dbMutex);
  std::vector<BlockedEvent> out;
  if (db == nullptr) {
    return out;
  }

  const char *sql =
      "SELECT id, timestamp, domain, protocol, source_ip, destination_ip, "
      "reason FROM blocked_events ORDER BY timestamp DESC, id DESC LIMIT ?;";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    return out;
  }

  sqlite3_bind_int(stmt, 1, limit);
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    BlockedEvent rec;
    rec.id = sqlite3_column_int(stmt, 0);
    rec.timestamp = columnText(stmt, 1);
    rec.domain = columnText(stmt, 2);
    rec.protocol = columnText(stmt, 3);
    rec.source_ip = columnText(stmt, 4);
    rec.destination_ip = columnText(stmt, 5);
    rec.reason = columnText(stmt, 6);
    out.push_back(rec);
  }

  sqlite3_finalize(stmt);
  return out;
}

BlockedStats Database::getBlockedStats() {
  std::lock_guard<std::recursive_mutex> lock(dbMutex);
  BlockedStats stats;
  if (db == nullptr) {
    return stats;
  }

  const std::string today = currentUtcDatePrefix();
  const std::string todayPattern = today + "%";

  const char *countSql = R"SQL(
        SELECT
            COUNT(*) AS total_today,
            SUM(CASE WHEN protocol = 'UDP' THEN 1 ELSE 0 END) AS dns_count,
            SUM(CASE WHEN protocol = 'TCP' THEN 1 ELSE 0 END) AS tls_count
        FROM blocked_events
        WHERE timestamp LIKE ?;
    )SQL";

  sqlite3_stmt *countStmt = nullptr;
  if (sqlite3_prepare_v2(db, countSql, -1, &countStmt, nullptr) == SQLITE_OK) {
    sqlite3_bind_text(countStmt, 1, todayPattern.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(countStmt) == SQLITE_ROW) {
      stats.blocked_today = sqlite3_column_int(countStmt, 0);
      stats.blocked_dns = sqlite3_column_int(countStmt, 1);
      stats.blocked_tls = sqlite3_column_int(countStmt, 2);
    }
  }
  sqlite3_finalize(countStmt);

  stats.top_domains = getBlockedDomains(10);
  return stats;
}

std::vector<DomainFrequency> Database::getBlockedDomains(int limit) {
  std::lock_guard<std::recursive_mutex> lock(dbMutex);
  std::vector<DomainFrequency> out;
  if (db == nullptr) {
    return out;
  }

  const char *sql =
      "SELECT domain, COUNT(*) AS count FROM blocked_events WHERE domain <> '' "
      "GROUP BY domain ORDER BY count DESC, domain ASC LIMIT ?;";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    return out;
  }

  sqlite3_bind_int(stmt, 1, limit);
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    DomainFrequency frequency;
    frequency.domain = columnText(stmt, 0);
    frequency.count = sqlite3_column_int(stmt, 1);
    out.push_back(frequency);
  }

  sqlite3_finalize(stmt);
  return out;
}

bool Database::insertFirewallAction(const FirewallAction &rec) {
  std::lock_guard<std::recursive_mutex> lock(dbMutex);
  if (db == nullptr) {
    return false;
  }

  const char *sql = "INSERT INTO firewall_actions (timestamp, domain, action, "
                    "backend, status, reason) VALUES (?, ?, ?, ?, ?, ?);";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    return false;
  }

  sqlite3_bind_text(stmt, 1, rec.timestamp.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, rec.domain.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 3, rec.action.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 4, rec.backend.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 5, rec.status.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 6, rec.reason.c_str(), -1, SQLITE_TRANSIENT);

  const bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  sqlite3_finalize(stmt);
  return ok;
}

std::vector<FirewallAction> Database::getFirewallActions(int limit) {
  std::lock_guard<std::recursive_mutex> lock(dbMutex);
  std::vector<FirewallAction> out;
  if (db == nullptr) {
    return out;
  }

  const char *sql =
      "SELECT id, timestamp, domain, action, backend, status, reason FROM "
      "firewall_actions ORDER BY timestamp DESC, id DESC LIMIT ?;";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    return out;
  }

  sqlite3_bind_int(stmt, 1, limit);
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    FirewallAction rec;
    rec.id = sqlite3_column_int(stmt, 0);
    rec.timestamp = columnText(stmt, 1);
    rec.domain = columnText(stmt, 2);
    rec.action = columnText(stmt, 3);
    rec.backend = columnText(stmt, 4);
    rec.status = columnText(stmt, 5);
    rec.reason = columnText(stmt, 6);
    out.push_back(rec);
  }

  sqlite3_finalize(stmt);
  return out;
}

bool Database::clearFirewallData() {
  std::lock_guard<std::recursive_mutex> lock(dbMutex);
  if (db == nullptr) {
    return false;
  }
  char *err = nullptr;
  if (sqlite3_exec(db, "DELETE FROM firewall_actions;", nullptr, nullptr, &err) != SQLITE_OK) {
    if (err) sqlite3_free(err);
    return false;
  }
  if (sqlite3_exec(db, "DELETE FROM blocked_events;", nullptr, nullptr, &err) != SQLITE_OK) {
    if (err) sqlite3_free(err);
    return false;
  }
  return true;
}

bool Database::insertThreatEvent(const ThreatEvent &rec) {
  std::lock_guard<std::recursive_mutex> lock(dbMutex);
  if (db == nullptr) {
    return false;
  }

  const char *sql =
      "INSERT INTO threat_events (timestamp, domain, category, severity, "
      "description, protocol, source_ip, destination_ip, reason) VALUES (?, ?, "
      "?, ?, ?, ?, ?, ?, ?);";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    return false;
  }

  sqlite3_bind_text(stmt, 1, rec.timestamp.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, rec.domain.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 3, rec.category.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 4, rec.severity.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 5, rec.description.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 6, rec.protocol.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 7, rec.source_ip.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 8, rec.destination_ip.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 9, rec.description.c_str(), -1, SQLITE_TRANSIENT);

  const bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  sqlite3_finalize(stmt);
  return ok;
}

bool Database::insertSecurityAnalysis(const SecurityAnalysisRecord &rec) {
  std::lock_guard<std::recursive_mutex> lock(dbMutex);
  if (db == nullptr) {
    return false;
  }

  const char *sql =
      "INSERT INTO security_analysis (timestamp, domain, source_ip, "
      "destination_ip, protocol, event_type, category, severity, confidence, "
      "score, explanation, recommendation) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, "
      "?, ?, ?);";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    return false;
  }

  sqlite3_bind_text(stmt, 1, rec.timestamp.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, rec.domain.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 3, rec.source_ip.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 4, rec.destination_ip.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 5, rec.protocol.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 6, rec.event_type.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 7, rec.category.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 8, rec.severity.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 9, rec.confidence.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 10, rec.score);
  sqlite3_bind_text(stmt, 11, rec.explanation.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 12, rec.recommendation.c_str(), -1, SQLITE_TRANSIENT);

  const bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  sqlite3_finalize(stmt);
  return ok;
}

std::vector<SecurityAnalysisRecord> Database::getSecurityAnalyses(int limit) {
  std::lock_guard<std::recursive_mutex> lock(dbMutex);
  std::vector<SecurityAnalysisRecord> out;
  if (db == nullptr) {
    return out;
  }

  const char *sql = "SELECT id, timestamp, domain, source_ip, destination_ip, "
                    "protocol, event_type, category, severity, confidence, "
                    "score, explanation, recommendation FROM security_analysis "
                    "ORDER BY timestamp DESC, id DESC LIMIT ?;";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    return out;
  }

  sqlite3_bind_int(stmt, 1, limit);
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    SecurityAnalysisRecord rec;
    rec.id = sqlite3_column_int(stmt, 0);
    rec.timestamp = columnText(stmt, 1);
    rec.domain = columnText(stmt, 2);
    rec.source_ip = columnText(stmt, 3);
    rec.destination_ip = columnText(stmt, 4);
    rec.protocol = columnText(stmt, 5);
    rec.event_type = columnText(stmt, 6);
    rec.category = columnText(stmt, 7);
    rec.severity = columnText(stmt, 8);
    rec.confidence = columnText(stmt, 9);
    rec.score = sqlite3_column_int(stmt, 10);
    rec.explanation = columnText(stmt, 11);
    rec.recommendation = columnText(stmt, 12);
    out.push_back(rec);
  }

  sqlite3_finalize(stmt);
  return out;
}

SecurityOverviewRecord Database::getSecurityOverview() {
  std::lock_guard<std::recursive_mutex> lock(dbMutex);
  SecurityOverviewRecord overview;
  if (db == nullptr) {
    return overview;
  }

  const std::string today = currentUtcDatePrefix();
  const std::string todayPattern = today + "%";

  const char *countSql =
      "SELECT COUNT(*), SUM(CASE WHEN severity = 'Critical' THEN 1 ELSE 0 "
      "END), SUM(CASE WHEN severity = 'High' THEN 1 ELSE 0 END), "
      "COALESCE(AVG(score), 0), COALESCE(MAX(score), 0) FROM security_analysis "
      "WHERE timestamp LIKE ?;";
  sqlite3_stmt *countStmt = nullptr;
  if (sqlite3_prepare_v2(db, countSql, -1, &countStmt, nullptr) == SQLITE_OK) {
    sqlite3_bind_text(countStmt, 1, todayPattern.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(countStmt) == SQLITE_ROW) {
      overview.total_incidents_today = sqlite3_column_int(countStmt, 0);
      overview.critical_incidents = sqlite3_column_int(countStmt, 1);
      overview.high_incidents = sqlite3_column_int(countStmt, 2);
      overview.average_score = sqlite3_column_int(countStmt, 3);
      overview.latest_score = sqlite3_column_int(countStmt, 4);
    }
  }
  sqlite3_finalize(countStmt);

  const char *categorySql =
      "SELECT category, COUNT(*) FROM security_analysis WHERE category <> '' "
      "GROUP BY category ORDER BY COUNT(*) DESC, category ASC LIMIT 10;";
  sqlite3_stmt *categoryStmt = nullptr;
  if (sqlite3_prepare_v2(db, categorySql, -1, &categoryStmt, nullptr) ==
      SQLITE_OK) {
    while (sqlite3_step(categoryStmt) == SQLITE_ROW) {
      LabelFrequency row;
      row.label = columnText(categoryStmt, 0);
      row.count = sqlite3_column_int(categoryStmt, 1);
      overview.categories.push_back(row);
    }
  }
  sqlite3_finalize(categoryStmt);

  const char *severitySql =
      "SELECT severity, COUNT(*) FROM security_analysis WHERE severity <> '' "
      "GROUP BY severity ORDER BY COUNT(*) DESC, severity ASC LIMIT 10;";
  sqlite3_stmt *severityStmt = nullptr;
  if (sqlite3_prepare_v2(db, severitySql, -1, &severityStmt, nullptr) ==
      SQLITE_OK) {
    while (sqlite3_step(severityStmt) == SQLITE_ROW) {
      LabelFrequency row;
      row.label = columnText(severityStmt, 0);
      row.count = sqlite3_column_int(severityStmt, 1);
      overview.severities.push_back(row);
    }
  }
  sqlite3_finalize(severityStmt);

  const char *domainSql =
      "SELECT domain, COUNT(*) FROM security_analysis WHERE domain <> '' GROUP "
      "BY domain ORDER BY COUNT(*) DESC, domain ASC LIMIT 10;";
  sqlite3_stmt *domainStmt = nullptr;
  if (sqlite3_prepare_v2(db, domainSql, -1, &domainStmt, nullptr) ==
      SQLITE_OK) {
    while (sqlite3_step(domainStmt) == SQLITE_ROW) {
      DomainFrequency row;
      row.domain = columnText(domainStmt, 0);
      row.count = sqlite3_column_int(domainStmt, 1);
      overview.top_domains.push_back(row);
    }
  }
  sqlite3_finalize(domainStmt);

  const char *feedSql =
      "SELECT COUNT(*) FROM threat_feed_updates WHERE timestamp LIKE ?;";
  sqlite3_stmt *feedStmt = nullptr;
  if (sqlite3_prepare_v2(db, feedSql, -1, &feedStmt, nullptr) == SQLITE_OK) {
    sqlite3_bind_text(feedStmt, 1, todayPattern.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(feedStmt) == SQLITE_ROW) {
      overview.feed_updates_today = sqlite3_column_int(feedStmt, 0);
    }
  }
  sqlite3_finalize(feedStmt);

  const char *activeThreatsSql =
      "SELECT COUNT(*) FROM threat_events WHERE timestamp LIKE ?;";
  sqlite3_stmt *activeThreatsStmt = nullptr;
  if (sqlite3_prepare_v2(db, activeThreatsSql, -1, &activeThreatsStmt,
                         nullptr) == SQLITE_OK) {
    sqlite3_bind_text(activeThreatsStmt, 1, todayPattern.c_str(), -1,
                      SQLITE_TRANSIENT);
    if (sqlite3_step(activeThreatsStmt) == SQLITE_ROW) {
      overview.active_threats = sqlite3_column_int(activeThreatsStmt, 0);
    }
  }
  sqlite3_finalize(activeThreatsStmt);

  return overview;
}

bool Database::insertThreatFeedUpdate(const ThreatFeedUpdateRecord &rec) {
  std::lock_guard<std::recursive_mutex> lock(dbMutex);
  if (db == nullptr) {
    return false;
  }

  const char *sql =
      "INSERT INTO threat_feed_updates (timestamp, source, status, "
      "sources_checked, indicators_loaded, message) VALUES (?, ?, ?, ?, ?, ?);";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    return false;
  }

  sqlite3_bind_text(stmt, 1, rec.timestamp.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, rec.source.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 3, rec.status.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 4, rec.sources_checked);
  sqlite3_bind_int(stmt, 5, rec.indicators_loaded);
  sqlite3_bind_text(stmt, 6, rec.message.c_str(), -1, SQLITE_TRANSIENT);

  const bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  sqlite3_finalize(stmt);
  return ok;
}

std::vector<ThreatFeedUpdateRecord> Database::getThreatFeedUpdates(int limit) {
  std::lock_guard<std::recursive_mutex> lock(dbMutex);
  std::vector<ThreatFeedUpdateRecord> out;
  if (db == nullptr) {
    return out;
  }

  const char *sql = "SELECT id, timestamp, source, status, sources_checked, "
                    "indicators_loaded, message FROM threat_feed_updates ORDER "
                    "BY timestamp DESC, id DESC LIMIT ?;";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    return out;
  }

  sqlite3_bind_int(stmt, 1, limit);
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    ThreatFeedUpdateRecord rec;
    rec.id = sqlite3_column_int(stmt, 0);
    rec.timestamp = columnText(stmt, 1);
    rec.source = columnText(stmt, 2);
    rec.status = columnText(stmt, 3);
    rec.sources_checked = sqlite3_column_int(stmt, 4);
    rec.indicators_loaded = sqlite3_column_int(stmt, 5);
    rec.message = columnText(stmt, 6);
    out.push_back(rec);
  }

  sqlite3_finalize(stmt);
  return out;
}

bool Database::upsertThreatFeedStatus(const ThreatFeedStatusRecord &rec) {
  std::lock_guard<std::recursive_mutex> lock(dbMutex);
  if (db == nullptr) {
    return false;
  }

  const char *sql = R"SQL(
        INSERT INTO threat_feeds (name, type, location, status, last_update, next_update, threat_count, version, health, error)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET
            type = excluded.type,
            location = excluded.location,
            status = excluded.status,
            last_update = excluded.last_update,
            next_update = excluded.next_update,
            threat_count = excluded.threat_count,
            version = excluded.version,
            health = excluded.health,
            error = excluded.error;
    )SQL";

  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    return false;
  }

  sqlite3_bind_text(stmt, 1, rec.name.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 2, rec.type.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 3, rec.location.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 4, rec.status.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 5, rec.last_update.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 6, rec.next_update.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_int(stmt, 7, rec.threat_count);
  sqlite3_bind_text(stmt, 8, rec.version.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 9, rec.health.c_str(), -1, SQLITE_TRANSIENT);
  sqlite3_bind_text(stmt, 10, rec.error.c_str(), -1, SQLITE_TRANSIENT);

  const bool ok = sqlite3_step(stmt) == SQLITE_DONE;
  sqlite3_finalize(stmt);
  return ok;
}

std::vector<ThreatFeedStatusRecord> Database::getThreatFeedStatuses(int limit) {
  std::lock_guard<std::recursive_mutex> lock(dbMutex);
  std::vector<ThreatFeedStatusRecord> out;
  if (db == nullptr) {
    return out;
  }

  const char *sql = "SELECT id, name, type, location, status, last_update, "
                    "next_update, threat_count, version, health, error FROM "
                    "threat_feeds ORDER BY name ASC LIMIT ?;";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    return out;
  }

  sqlite3_bind_int(stmt, 1, limit);
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    ThreatFeedStatusRecord rec;
    rec.id = sqlite3_column_int(stmt, 0);
    rec.name = columnText(stmt, 1);
    rec.type = columnText(stmt, 2);
    rec.location = columnText(stmt, 3);
    rec.status = columnText(stmt, 4);
    rec.last_update = columnText(stmt, 5);
    rec.next_update = columnText(stmt, 6);
    rec.threat_count = sqlite3_column_int(stmt, 7);
    rec.version = columnText(stmt, 8);
    rec.health = columnText(stmt, 9);
    rec.error = columnText(stmt, 10);
    out.push_back(rec);
  }

  sqlite3_finalize(stmt);
  return out;
}

std::vector<ThreatEvent> Database::getThreatEvents(int limit) {
  std::lock_guard<std::recursive_mutex> lock(dbMutex);
  std::vector<ThreatEvent> out;
  if (db == nullptr) {
    return out;
  }

  const char *sql =
      "SELECT id, timestamp, domain, category, severity, COALESCE(description, "
      "reason), protocol, source_ip, destination_ip FROM threat_events ORDER "
      "BY timestamp DESC, id DESC LIMIT ?;";
  sqlite3_stmt *stmt = nullptr;
  if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
    return out;
  }

  sqlite3_bind_int(stmt, 1, limit);
  while (sqlite3_step(stmt) == SQLITE_ROW) {
    ThreatEvent rec;
    rec.id = sqlite3_column_int(stmt, 0);
    rec.timestamp = columnText(stmt, 1);
    rec.domain = columnText(stmt, 2);
    rec.category = columnText(stmt, 3);
    rec.severity = columnText(stmt, 4);
    rec.description = columnText(stmt, 5);
    rec.protocol = columnText(stmt, 6);
    rec.source_ip = columnText(stmt, 7);
    rec.destination_ip = columnText(stmt, 8);
    out.push_back(rec);
  }

  sqlite3_finalize(stmt);
  return out;
}

ThreatStats Database::getThreatStats() {
  std::lock_guard<std::recursive_mutex> lock(dbMutex);
  ThreatStats stats;
  if (db == nullptr) {
    return stats;
  }

  const std::string today = currentUtcDatePrefix();
  const std::string todayPattern = today + "%";

  const char *countSql =
      "SELECT COUNT(*) FROM threat_events WHERE timestamp LIKE ?;";
  sqlite3_stmt *countStmt = nullptr;
  if (sqlite3_prepare_v2(db, countSql, -1, &countStmt, nullptr) == SQLITE_OK) {
    sqlite3_bind_text(countStmt, 1, todayPattern.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(countStmt) == SQLITE_ROW) {
      stats.total_threats_today = sqlite3_column_int(countStmt, 0);
    }
  }
  sqlite3_finalize(countStmt);

  const char *categorySql =
      "SELECT category, COUNT(*) FROM threat_events WHERE category <> '' GROUP "
      "BY category ORDER BY COUNT(*) DESC, category ASC LIMIT 10;";
  sqlite3_stmt *categoryStmt = nullptr;
  if (sqlite3_prepare_v2(db, categorySql, -1, &categoryStmt, nullptr) ==
      SQLITE_OK) {
    while (sqlite3_step(categoryStmt) == SQLITE_ROW) {
      LabelFrequency row;
      row.label = columnText(categoryStmt, 0);
      row.count = sqlite3_column_int(categoryStmt, 1);
      stats.categories.push_back(row);
    }
  }
  sqlite3_finalize(categoryStmt);

  const char *severitySql =
      "SELECT severity, COUNT(*) FROM threat_events WHERE severity <> '' GROUP "
      "BY severity ORDER BY COUNT(*) DESC, severity ASC LIMIT 10;";
  sqlite3_stmt *severityStmt = nullptr;
  if (sqlite3_prepare_v2(db, severitySql, -1, &severityStmt, nullptr) ==
      SQLITE_OK) {
    while (sqlite3_step(severityStmt) == SQLITE_ROW) {
      LabelFrequency row;
      row.label = columnText(severityStmt, 0);
      row.count = sqlite3_column_int(severityStmt, 1);
      stats.severity_distribution.push_back(row);
    }
  }
  sqlite3_finalize(severityStmt);

  const char *domainSql =
      "SELECT domain, COUNT(*) FROM threat_events WHERE domain <> '' GROUP BY "
      "domain ORDER BY COUNT(*) DESC, domain ASC LIMIT 10;";
  sqlite3_stmt *domainStmt = nullptr;
  if (sqlite3_prepare_v2(db, domainSql, -1, &domainStmt, nullptr) ==
      SQLITE_OK) {
    while (sqlite3_step(domainStmt) == SQLITE_ROW) {
      DomainFrequency row;
      row.domain = columnText(domainStmt, 0);
      row.count = sqlite3_column_int(domainStmt, 1);
      stats.top_domains.push_back(row);
    }
  }
  sqlite3_finalize(domainStmt);

  return stats;
}
