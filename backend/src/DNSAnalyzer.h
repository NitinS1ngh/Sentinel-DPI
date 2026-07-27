#pragma once
#include <string>

#include "Database.h"

class DNSAnalyzer {
public:
    explicit DNSAnalyzer(Database *db);
    ~DNSAnalyzer();

    // Analyze DNS layer and store results
    void analyze(const void* dnsLayerRaw, const std::string &srcIp);

private:
    Database *database;
};
