#include "FirewallBackend.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <unordered_set>

#ifdef __APPLE__
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#endif

namespace {
std::string trim(const std::string &value) {
    const auto begin = std::find_if_not(value.begin(), value.end(), [](unsigned char ch) { return std::isspace(ch); });
    const auto end = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char ch) { return std::isspace(ch); }).base();
    if (begin >= end) {
        return "";
    }
    return std::string(begin, end);
}

std::string normalize(std::string domain) {
    domain = trim(domain);
    if (domain.rfind("*.", 0) == 0) {
        domain = domain.substr(2);
    }
    if (!domain.empty() && domain.back() == '.') {
        domain.pop_back();
    }
    std::transform(domain.begin(), domain.end(), domain.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return domain;
}

void appendUnique(std::vector<std::string> &values, const std::string &next) {
    if (std::find(values.begin(), values.end(), next) == values.end()) {
        values.push_back(next);
    }
}
} // namespace

bool MockFirewallBackend::blockDomain(const std::string &domain) {
    const std::string normalized = normalize(domain);
    if (normalized.empty()) {
        return false;
    }

    appendUnique(blockedDomains, normalized);
    return true;
}

bool MockFirewallBackend::unblockDomain(const std::string &domain) {
    const std::string normalized = normalize(domain);
    if (normalized.empty()) {
        return false;
    }

    blockedDomains.erase(
        std::remove(blockedDomains.begin(), blockedDomains.end(), normalized),
        blockedDomains.end()
    );
    return true;
}

std::vector<std::string> MockFirewallBackend::getBlockedDomains() {
    auto values = blockedDomains;
    std::sort(values.begin(), values.end());
    return values;
}

std::string MockFirewallBackend::name() const {
    return "Mock";
}

bool MockFirewallBackend::clearRules() {
    blockedDomains.clear();
    return true;
}

std::string MacOSPfBackend::normalizeDomain(const std::string &domain) {
    return normalize(domain);
}

MacOSPfBackend::MacOSPfBackend() {
#ifdef __APPLE__
    // Enable pf
    std::system("pfctl -e >/dev/null 2>&1");
    // Append anchor reference to current /etc/pf.conf rules and load them
    std::system("(cat /etc/pf.conf 2>/dev/null; echo \"anchor \\\"sentineldpi/*\\\"\") | pfctl -f - >/dev/null 2>&1");
#endif
}

MacOSPfBackend::~MacOSPfBackend() {
    clearRules();
}

std::vector<std::string> MacOSPfBackend::resolveDomainAddresses(const std::string &domain) {
    std::vector<std::string> addresses;

#ifdef __APPLE__
    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    addrinfo *result = nullptr;
    if (getaddrinfo(domain.c_str(), nullptr, &hints, &result) != 0) {
        return addresses;
    }

    for (addrinfo *node = result; node != nullptr; node = node->ai_next) {
        char buffer[INET6_ADDRSTRLEN] = {0};
        if (node->ai_family == AF_INET) {
            auto *addr = reinterpret_cast<sockaddr_in*>(node->ai_addr);
            if (inet_ntop(AF_INET, &addr->sin_addr, buffer, sizeof(buffer)) != nullptr) {
                appendUnique(addresses, buffer);
            }
        } else if (node->ai_family == AF_INET6) {
            auto *addr = reinterpret_cast<sockaddr_in6*>(node->ai_addr);
            if (inet_ntop(AF_INET6, &addr->sin6_addr, buffer, sizeof(buffer)) != nullptr) {
                appendUnique(addresses, buffer);
            }
        }
    }

    freeaddrinfo(result);
#else
    (void)domain;
#endif

    return addresses;
}

bool MacOSPfBackend::applyRules() {
#ifdef __APPLE__
    const std::string anchorPath = "/tmp/sentineldpi_pf_anchor.conf";
    std::ofstream file(anchorPath, std::ios::trunc);
    if (!file.is_open()) {
        return false;
    }

    file << "# Sentinel DPI pf anchor\n";

    for (const auto &domain : blockedDomains) {
        const auto addresses = resolveDomainAddresses(domain);
        if (addresses.empty()) {
            continue;
        }

        file << "# " << domain << "\n";
        file << "block drop quick to { ";
        for (std::size_t index = 0; index < addresses.size(); ++index) {
            if (index > 0) {
                file << ", ";
            }
            file << addresses[index];
        }
        file << " }\n";
    }

    file.close();
    const std::string command = "pfctl -a sentineldpi/blocklist -f " + anchorPath;
    return std::system(command.c_str()) == 0;
#else
    return false;
#endif
}

bool MacOSPfBackend::blockDomain(const std::string &domain) {
    const std::string normalized = normalizeDomain(domain);
    if (normalized.empty()) {
        return false;
    }

    appendUnique(blockedDomains, normalized);
    return applyRules();
}

bool MacOSPfBackend::unblockDomain(const std::string &domain) {
    const std::string normalized = normalizeDomain(domain);
    if (normalized.empty()) {
        return false;
    }

    blockedDomains.erase(
        std::remove(blockedDomains.begin(), blockedDomains.end(), normalized),
        blockedDomains.end()
    );
    return applyRules();
}

std::vector<std::string> MacOSPfBackend::getBlockedDomains() {
    auto values = blockedDomains;
    std::sort(values.begin(), values.end());
    return values;
}

bool MacOSPfBackend::clearRules() {
    blockedDomains.clear();
    return applyRules();
}

std::string MacOSPfBackend::name() const {
    return "macOS pf";
}

std::unique_ptr<FirewallBackend> createFirewallBackend(const std::string &backendName) {
    const std::string normalized = normalize(backendName);
    if (normalized == "pf" || normalized == "macospf" || normalized == "macos pf") {
#ifdef __APPLE__
        return std::make_unique<MacOSPfBackend>();
#else
        std::cerr << "FirewallBackend: pf selected but current platform is not macOS, falling back to Mock\n";
        return std::make_unique<MockFirewallBackend>();
#endif
    }

    return std::make_unique<MockFirewallBackend>();
}