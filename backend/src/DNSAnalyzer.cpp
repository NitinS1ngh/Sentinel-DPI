#include "DNSAnalyzer.h"
#include "Database.h"
#include <iostream>
#include <ctime>

#ifdef USE_PCAPPP
#include <DnsLayer.h>
using namespace pcpp;
#endif

DNSAnalyzer::DNSAnalyzer(Database *db) : database(db) {}
DNSAnalyzer::~DNSAnalyzer() = default;

void DNSAnalyzer::analyze(const void* dnsLayerRaw, const std::string &srcIp) {
#ifdef USE_PCAPPP
    if (!dnsLayerRaw || !database) return;
    const pcpp::DnsLayer* dns = reinterpret_cast<const pcpp::DnsLayer*>(dnsLayerRaw);
    if (!dns) return;

    std::string qname = dns->toString();
    std::string qtype = "DNS";

    // timestamp
    std::time_t t = std::time(nullptr);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));

    // Best-effort process_name unknown for now
    // Insert into DB
    // Use Database API
    struct DNSRecord rec;
    rec.timestamp = buf;
    rec.src_ip = srcIp;
    rec.query_name = qname;
    rec.query_type = qtype;
    rec.process_name = "";

    database->insertDNSQuery(rec);
#else
    (void)dnsLayerRaw; (void)srcIp;
#endif
}
