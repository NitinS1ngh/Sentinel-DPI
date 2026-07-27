#pragma once

#include <memory>
#include <string>
#include <vector>

class FirewallBackend {
public:
    virtual ~FirewallBackend() = default;

    virtual bool blockDomain(const std::string &domain) = 0;
    virtual bool unblockDomain(const std::string &domain) = 0;
    virtual std::vector<std::string> getBlockedDomains() = 0;
    virtual bool clearRules() = 0;
    virtual std::string name() const = 0;
};

class MockFirewallBackend : public FirewallBackend {
public:
    bool blockDomain(const std::string &domain) override;
    bool unblockDomain(const std::string &domain) override;
    std::vector<std::string> getBlockedDomains() override;
    bool clearRules() override;
    std::string name() const override;

private:
    std::vector<std::string> blockedDomains;
};

class MacOSPfBackend : public FirewallBackend {
public:
    MacOSPfBackend();
    ~MacOSPfBackend() override;
    bool blockDomain(const std::string &domain) override;
    bool unblockDomain(const std::string &domain) override;
    std::vector<std::string> getBlockedDomains() override;
    bool clearRules() override;
    std::string name() const override;

private:
    bool applyRules();
    static std::string normalizeDomain(const std::string &domain);
    static std::vector<std::string> resolveDomainAddresses(const std::string &domain);

    std::vector<std::string> blockedDomains;
};

std::unique_ptr<FirewallBackend> createFirewallBackend(const std::string &backendName);