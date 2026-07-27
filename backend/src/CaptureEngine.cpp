#include "CaptureEngine.h"
#include <atomic>
#include <chrono>
#include <ctime>
#include <iostream>
#include <pcap.h>
#include <sstream>
#include <vector>

#ifdef USE_PCAPPP
#include <DnsLayer.h>
#include <IPv4Layer.h>
#include <Packet.h>
#include <PcapLiveDevice.h>
#include <PcapLiveDeviceList.h>
#include <SSLHandshake.h>
#include <SSLLayer.h>
#include <TcpLayer.h>
#include <UdpLayer.h>

using namespace pcpp;

namespace {
std::string safeGetIPv4Address(pcpp::PcapLiveDevice *d) {
  if (!d)
    return "0.0.0.0";
  try {
    return d->getIPv4Address().toString();
  } catch (...) {
    return "0.0.0.0";
  }
}

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
    case '\\':
      escaped += "\\\\";
      break;
    case '"':
      escaped += "\\\"";
      break;
    case '\b':
      escaped += "\\b";
      break;
    case '\f':
      escaped += "\\f";
      break;
    case '\n':
      escaped += "\\n";
      break;
    case '\r':
      escaped += "\\r";
      break;
    case '\t':
      escaped += "\\t";
      break;
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

std::string buildTrafficEventJson(const TrafficEvent &event) {
  std::ostringstream ss;
  ss << "{"
     << "\"type\":\"" << escapeJson(event.event_type) << "\","
     << "\"domain\":\"" << escapeJson(event.domain) << "\","
     << "\"timestamp\":\"" << escapeJson(event.timestamp) << "\","
     << "\"source_ip\":\"" << escapeJson(event.source_ip) << "\","
     << "\"destination_ip\":\"" << escapeJson(event.destination_ip) << "\","
     << "\"protocol\":\"" << escapeJson(event.protocol) << "\""
     << "}";
  return ss.str();
}

std::string buildPolicyEventJson(const PolicyEvent &event) {
  std::ostringstream ss;
  ss << "{"
     << "\"type\":\"POLICY\","
     << "\"domain\":\"" << escapeJson(event.domain) << "\","
     << "\"timestamp\":\"" << escapeJson(event.timestamp) << "\","
     << "\"policy_type\":\"" << escapeJson(event.policy_type) << "\","
     << "\"source_ip\":\"" << escapeJson(event.source_ip) << "\""
     << "}";
  return ss.str();
}

std::string buildThreatEventJson(const ThreatEvent &event) {
  std::ostringstream ss;
  ss << "{";
  ss << "\"type\":\"THREAT\",";
  ss << "\"domain\":\"" << escapeJson(event.domain) << "\",";
  ss << "\"category\":\"" << escapeJson(event.category) << "\",";
  ss << "\"severity\":\"" << escapeJson(event.severity) << "\",";
  ss << "\"description\":\"" << escapeJson(event.description) << "\",";
  ss << "\"timestamp\":\"" << escapeJson(event.timestamp) << "\",";
  ss << "\"protocol\":\"" << escapeJson(event.protocol) << "\",";
  ss << "\"source_ip\":\"" << escapeJson(event.source_ip) << "\",";
  ss << "\"destination_ip\":\"" << escapeJson(event.destination_ip) << "\"";
  ss << "}";
  return ss.str();
}

std::string buildSecurityAnalysisJson(const SecurityAnalysisRecord &event) {
  std::ostringstream ss;
  ss << "{";
  ss << "\"type\":\"SECURITY_ANALYSIS\",";
  ss << "\"domain\":\"" << escapeJson(event.domain) << "\",";
  ss << "\"timestamp\":\"" << escapeJson(event.timestamp) << "\",";
  ss << "\"source_ip\":\"" << escapeJson(event.source_ip) << "\",";
  ss << "\"destination_ip\":\"" << escapeJson(event.destination_ip) << "\",";
  ss << "\"protocol\":\"" << escapeJson(event.protocol) << "\",";
  ss << "\"event_type\":\"" << escapeJson(event.event_type) << "\",";
  ss << "\"category\":\"" << escapeJson(event.category) << "\",";
  ss << "\"severity\":\"" << escapeJson(event.severity) << "\",";
  ss << "\"confidence\":\"" << escapeJson(event.confidence) << "\",";
  ss << "\"score\":" << event.score << ",";
  ss << "\"explanation\":\"" << escapeJson(event.explanation) << "\",";
  ss << "\"recommendation\":\"" << escapeJson(event.recommendation) << "\"";
  ss << "}";
  return ss.str();
}

struct DnsObservation {
  std::string sourceIp;
  std::string destinationIp;
  std::vector<std::string> queryNames;
};

struct TlsObservation {
  std::string sourceIp;
  std::string destinationIp;
  std::string tlsVersion;
  std::vector<std::string> sniHostnames;
};

DnsObservation buildDnsObservation(const IPv4Layer *ipLayer,
                                   const DnsLayer *dnsLayer) {
  DnsObservation observation;
  if (ipLayer != nullptr) {
    observation.sourceIp = ipLayer->getSrcIPAddress().toString();
    observation.destinationIp = ipLayer->getDstIPAddress().toString();
  }

  if (dnsLayer != nullptr) {
    for (DnsQuery *query = dnsLayer->getFirstQuery(); query != nullptr;
         query = dnsLayer->getNextQuery(query)) {
      const std::string queryName = query->getName();
      if (!queryName.empty()) {
        observation.queryNames.push_back(queryName);
      }
    }
  }

  return observation;
}

TlsObservation buildTlsObservation(const IPv4Layer *ipLayer,
                                   const SSLHandshakeLayer *sslLayer) {
  TlsObservation observation;
  if (ipLayer != nullptr) {
    observation.sourceIp = ipLayer->getSrcIPAddress().toString();
    observation.destinationIp = ipLayer->getDstIPAddress().toString();
  }

  if (sslLayer == nullptr) {
    return observation;
  }

  for (size_t index = 0; index < sslLayer->getHandshakeMessagesCount();
       ++index) {
    SSLHandshakeMessage *handshakeMessage =
        sslLayer->getHandshakeMessageAt(static_cast<int>(index));
    if (handshakeMessage == nullptr) {
      continue;
    }

    if (handshakeMessage->getHandshakeType() != SSL_CLIENT_HELLO) {
      continue;
    }

    auto *clientHello = static_cast<SSLClientHelloMessage *>(handshakeMessage);
    if (clientHello == nullptr) {
      continue;
    }

    std::cerr << "CaptureEngine: ClientHello detected\n";
    observation.tlsVersion = clientHello->getHandshakeVersion().toString(true);

    SSLServerNameIndicationExtension *sniExtension =
        clientHello->getExtensionOfType<SSLServerNameIndicationExtension>();
    if (sniExtension != nullptr) {
      const std::string hostName = sniExtension->getHostName();
      if (!hostName.empty()) {
        observation.sniHostnames.push_back(hostName);
      }
    }
  }

  return observation;
}

} // namespace

void CaptureEngine::onPacketArrives(RawPacket *rawPacket, PcapLiveDevice *dev,
                                    void *cookie) {
  CaptureEngine *engine = reinterpret_cast<CaptureEngine *>(cookie);
  if (!engine || !(engine->database))
    return;

  static std::atomic<uint64_t> packetCount{0};
  const uint64_t currentCount = ++packetCount;
  if (currentCount <= 5 || currentCount % 50 == 0) {
    std::cerr << "CaptureEngine: packet #" << currentCount << " on "
              << (dev ? dev->getName() : "unknown")
              << " len=" << rawPacket->getRawDataLen() << "\n";
  }

  Packet parsedPacket(rawPacket);
  IPv4Layer *ipLayer = parsedPacket.getLayerOfType<IPv4Layer>();
  TcpLayer *tcpLayer = parsedPacket.getLayerOfType<TcpLayer>();
  UdpLayer *udpLayer = parsedPacket.getLayerOfType<UdpLayer>();
  DnsLayer *dnsLayer = parsedPacket.getLayerOfType<DnsLayer>();
  SSLHandshakeLayer *sslLayer =
      parsedPacket.getLayerOfType<SSLHandshakeLayer>();

  const std::string sourceIp =
      ipLayer != nullptr ? ipLayer->getSrcIPAddress().toString() : "";
  const std::string destinationIp =
      ipLayer != nullptr ? ipLayer->getDstIPAddress().toString() : "";
  const std::string protocol =
      tcpLayer != nullptr ? "TCP" : (udpLayer != nullptr ? "UDP" : "UNKNOWN");

  if (dnsLayer != nullptr) {
    std::cerr << "CaptureEngine: DNS layer detected\n";
    const size_t queryCount = dnsLayer->getQueryCount();
    std::cerr << "CaptureEngine: Query count = " << queryCount << "\n";

    const DnsObservation observation = buildDnsObservation(ipLayer, dnsLayer);
    for (const std::string &queryName : observation.queryNames) {
      const std::string timestamp = currentUtcTimestamp();
      TrafficEvent event;
      event.timestamp = timestamp;
      event.event_type = "DNS";
      event.domain = queryName;
      event.source_ip = sourceIp;
      event.destination_ip = destinationIp;
      event.protocol = protocol;

      if (engine->database->insertTrafficEvent(event)) {
        std::cout << "[DB] Inserted DNS event: " << queryName << std::endl;
        if (engine->eventBroadcaster != nullptr) {
          engine->eventBroadcaster->broadcast(buildTrafficEventJson(event));
        }
      }
      std::cout << "DNS Query: " << queryName << std::endl;
      std::cerr << "CaptureEngine: Domain extracted = " << queryName << "\n";
      const auto threatMatches = engine->recordThreatMatches(
          timestamp, queryName, sourceIp, destinationIp, protocol);
      const auto policyMatches = engine->recordPolicyMatches(
          timestamp, queryName, sourceIp, destinationIp, protocol);
      engine->recordSecurityAnalysis(timestamp, queryName, sourceIp,
                                     destinationIp, protocol, "DNS",
                                     threatMatches, policyMatches);
    }
  }

  if (sslLayer != nullptr) {
    std::cerr << "CaptureEngine: TLS handshake detected\n";
    std::cerr << "CaptureEngine: Handshake message count = "
              << sslLayer->getHandshakeMessagesCount() << "\n";

    const TlsObservation observation = buildTlsObservation(ipLayer, sslLayer);
    if (!observation.tlsVersion.empty()) {
      std::cerr << "CaptureEngine: TLS version = " << observation.tlsVersion
                << "\n";
    }

    for (const std::string &sniHostName : observation.sniHostnames) {
      std::cerr << "CaptureEngine: SNI extracted = " << sniHostName << "\n";
      const std::string timestamp = currentUtcTimestamp();
      TrafficEvent event;
      event.timestamp = timestamp;
      event.event_type = "TLS";
      event.domain = sniHostName;
      event.source_ip = sourceIp;
      event.destination_ip = destinationIp;
      event.protocol = protocol;

      if (engine->database->insertTrafficEvent(event)) {
        std::cout << "[DB] Inserted TLS event: " << sniHostName << std::endl;
        if (engine->eventBroadcaster != nullptr) {
          engine->eventBroadcaster->broadcast(buildTrafficEventJson(event));
        }
      }
      std::cout << "TLS SNI: " << sniHostName << std::endl;
      const auto threatMatches = engine->recordThreatMatches(
          timestamp, sniHostName, sourceIp, destinationIp, protocol);
      const auto policyMatches = engine->recordPolicyMatches(
          timestamp, sniHostName, sourceIp, destinationIp, protocol);
      engine->recordSecurityAnalysis(timestamp, sniHostName, sourceIp,
                                     destinationIp, protocol, "TLS",
                                     threatMatches, policyMatches);
    }
  }
}

CaptureEngine::CaptureEngine(Database *db, const std::string &device,
                             EventBroadcaster *broadcaster,
                             BlockingEngine *blockingEngine,
                             ThreatIntelEngine *threatIntel,
                             SecurityIntelEngine *securityIntel)
    : database(db), policyEngine(), eventBroadcaster(broadcaster),
      blockingEngine(blockingEngine), threatIntel(threatIntel),
      securityIntel(securityIntel), deviceName(device) {}

CaptureEngine::~CaptureEngine() { stop(); }

void CaptureEngine::start() {
  if (running)
    return;
  running = true;

  std::vector<std::string> interfacesToCapture;
  interfacesToCapture.push_back(deviceName);

  pcap_if_t *alldevs;
  char errbuf[PCAP_ERRBUF_SIZE] = {0};
  if (pcap_findalldevs(&alldevs, errbuf) != -1) {
    for (pcap_if_t *d = alldevs; d != nullptr; d = d->next) {
      std::string name = d->name;
      if (name.rfind("utun", 0) == 0) {
        if (name != deviceName) {
          interfacesToCapture.push_back(name);
        }
      }
    }
    pcap_freealldevs(alldevs);
  }

  for (const std::string &iface : interfacesToCapture) {
    workers.emplace_back(&CaptureEngine::captureOnInterface, this, iface);
  }
}

void CaptureEngine::captureOnInterface(const std::string &interfaceName) {
  try {
    std::cerr << "CaptureEngine: thread starting for device " << interfaceName << "...\n";
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    // Set promiscuous mode to 0 to only capture host traffic
    pcap_t *pcap_handle =
        pcap_open_live(interfaceName.c_str(), 65535, 0, 100, errbuf);
    if (!pcap_handle) {
      std::cerr << "CaptureEngine: failed to open device " << interfaceName
                << ": " << errbuf << std::endl;
      return;
    }

    // Apply BPF filter to ignore broadcast and multicast noise
    bpf_program fp;
    const char *filter_exp = "not broadcast and not multicast";
    bpf_u_int32 net = 0, mask = 0;
    char lookup_errbuf[PCAP_ERRBUF_SIZE] = {0};
    if (pcap_lookupnet(interfaceName.c_str(), &net, &mask, lookup_errbuf) == -1) {
      net = 0;
      mask = 0;
    }
    if (pcap_compile(pcap_handle, &fp, filter_exp, 0, net) == 0) {
      pcap_setfilter(pcap_handle, &fp);
      pcap_freecode(&fp);
    } else {
      std::cerr << "CaptureEngine: failed to compile BPF filter on " << interfaceName
                << ": " << pcap_geterr(pcap_handle) << std::endl;
    }

    std::cout << "CaptureEngine: capturing on device " << interfaceName << " (host traffic only)" << std::endl;

    struct PcapCookie {
      CaptureEngine *engine;
      pcap_t *handle;
    };

    PcapCookie cookie = {this, pcap_handle};

    while (running) {
      int numPackets = pcap_dispatch(
          pcap_handle, 10,
          [](u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
            PcapCookie *cookie = reinterpret_cast<PcapCookie *>(user);
            if (!cookie || !cookie->engine)
              return;

            timeval tv = h->ts;
            int dlink = pcap_datalink(cookie->handle);
            pcpp::LinkLayerType linkType =
                static_cast<pcpp::LinkLayerType>(dlink);

            pcpp::RawPacket rawPacket(bytes, h->caplen, tv, false, linkType);
            CaptureEngine::onPacketArrives(&rawPacket, nullptr,
                                           cookie->engine);
          },
          reinterpret_cast<u_char *>(&cookie));

      if (numPackets < 0) {
        std::cerr << "CaptureEngine: error reading packets on " << interfaceName << std::endl;
        break;
      }
      if (numPackets == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
      }
    }

    pcap_close(pcap_handle);
    std::cout << "CaptureEngine: capture stopped on device " << interfaceName << std::endl;
  } catch (const std::exception &e) {
    std::cerr << "CaptureEngine exception on " << interfaceName << ": " << e.what() << "\n";
  } catch (...) {
    std::cerr << "CaptureEngine unknown exception on " << interfaceName << "\n";
  }
}

void CaptureEngine::stop() {
  if (!running)
    return;
  running = false;
  for (auto &w : workers) {
    if (w.joinable())
      w.join();
  }
  workers.clear();
}

std::vector<PolicyMatch> CaptureEngine::recordPolicyMatches(
    const std::string &timestamp, const std::string &domain,
    const std::string &sourceIp, const std::string &destinationIp,
    const std::string &protocol) {
  const std::vector<PolicyMatch> matches =
      policyEngine.evaluate(domain, sourceIp);
  for (const PolicyMatch &match : matches) {
    PolicyEvent event;
    event.timestamp = timestamp;
    event.domain = match.domain;
    event.policy_type = match.policy_type;
    event.source_ip = match.source_ip;
    if (database->insertPolicyEvent(event) && eventBroadcaster != nullptr) {
      eventBroadcaster->broadcast(buildPolicyEventJson(event));
    }

    if (match.policy_type == "BLOCKED" && blockingEngine != nullptr) {
      blockingEngine->handleBlockedMatch(match.domain, protocol, sourceIp,
                                         destinationIp, timestamp,
                                         "Matched blocked_domains.txt rule");
    }
  }
  return matches;
}

std::vector<ThreatMatch> CaptureEngine::recordThreatMatches(
    const std::string &timestamp, const std::string &domain,
    const std::string &sourceIp, const std::string &destinationIp,
    const std::string &protocol) {
  if (threatIntel == nullptr) {
    return {};
  }

  const auto matches = threatIntel->evaluate(domain);
  for (const auto &match : matches) {
    ThreatEvent event;
    event.timestamp = timestamp;
    event.domain = domain;
    event.category = match.indicator.category;
    event.severity = match.indicator.severity;
    event.description = match.indicator.description;
    event.protocol = protocol;
    event.source_ip = sourceIp;
    event.destination_ip = destinationIp;

    std::cerr << "[THREAT] Domain: " << event.domain << "\n";
    std::cerr << "[THREAT] Category: " << event.category << "\n";
    std::cerr << "[THREAT] Severity: " << event.severity << "\n";
    std::cerr << "[THREAT] Description: " << event.description << "\n";

    if (database != nullptr && database->insertThreatEvent(event)) {
      std::cerr << "[THREAT] Event Stored\n";
      if (eventBroadcaster != nullptr) {
        eventBroadcaster->broadcast(buildThreatEventJson(event));
        std::cerr << "[THREAT] Dashboard Updated\n";
      }
    }
  }
  return matches;
}

void CaptureEngine::recordSecurityAnalysis(
    const std::string &timestamp, const std::string &domain,
    const std::string &sourceIp, const std::string &destinationIp,
    const std::string &protocol, const std::string &eventType,
    const std::vector<ThreatMatch> &threatMatches,
    const std::vector<PolicyMatch> &policyMatches) {
  if (securityIntel == nullptr || database == nullptr) {
    return;
  }

  const SecurityAnalysis analysis =
      securityIntel->analyze(timestamp, domain, sourceIp, destinationIp,
                             protocol, eventType, threatMatches, policyMatches);

  SecurityAnalysisRecord record;
  record.timestamp = analysis.timestamp;
  record.domain = analysis.domain;
  record.source_ip = analysis.source_ip;
  record.destination_ip = analysis.destination_ip;
  record.protocol = analysis.protocol;
  record.event_type = analysis.event_type;
  record.category = analysis.category;
  record.severity = analysis.severity;
  record.confidence = analysis.confidence;
  record.score = analysis.score;
  record.explanation = analysis.explanation;
  record.recommendation = analysis.recommendation;

  if (database->insertSecurityAnalysis(record) && eventBroadcaster != nullptr) {
    eventBroadcaster->broadcast(buildSecurityAnalysisJson(record));
  }
}

#else

// Fallback stub when PcapPlusPlus not enabled

CaptureEngine::CaptureEngine(Database *db, const std::string &device,
                             EventBroadcaster *broadcaster,
                             BlockingEngine *blockingEngine,
                             ThreatIntelEngine *threatIntel,
                             SecurityIntelEngine *securityIntel)
    : database(db), policyEngine(), eventBroadcaster(broadcaster),
      blockingEngine(blockingEngine), threatIntel(threatIntel),
      securityIntel(securityIntel), deviceName(device) {}

CaptureEngine::~CaptureEngine() { stop(); }

void CaptureEngine::start() {
  if (running)
    return;
  running = true;
  worker = std::thread(&CaptureEngine::run, this);
}

void CaptureEngine::stop() {
  if (!running)
    return;
  running = false;
  if (worker.joinable())
    worker.join();
}

std::vector<ThreatMatch> CaptureEngine::recordThreatMatches(
    const std::string &timestamp, const std::string &domain,
    const std::string &sourceIp, const std::string &destinationIp,
    const std::string &protocol) {
  (void)timestamp;
  (void)domain;
  (void)sourceIp;
  (void)destinationIp;
  (void)protocol;
  return {};
}

void CaptureEngine::run() {
  std::cout << "CaptureEngine: started (stub)" << std::endl;
  while (running) {
    ConnectionRecord rec;
    std::time_t t = std::time(nullptr);
    char buf[64];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&t));
    rec.timestamp = buf;
    rec.process_name = "DemoProcess";
    rec.destination_ip = "93.184.216.34";
    rec.domain = "example.com";
    rec.protocol = "TCP";
    rec.port = 443;
    rec.bytes_sent = 512;
    rec.bytes_received = 1024;
    rec.action = "ALLOW";

    if (database)
      database->insertConnection(rec);

    std::this_thread::sleep_for(std::chrono::seconds(5));
  }
  std::cout << "CaptureEngine: stopped" << std::endl;
}

std::vector<PolicyMatch> CaptureEngine::recordPolicyMatches(
    const std::string &timestamp, const std::string &domain,
    const std::string &sourceIp, const std::string &destinationIp,
    const std::string &protocol) {
  (void)timestamp;
  (void)domain;
  (void)sourceIp;
  (void)destinationIp;
  (void)protocol;
  return {};
}

void CaptureEngine::recordSecurityAnalysis(
    const std::string &timestamp, const std::string &domain,
    const std::string &sourceIp, const std::string &destinationIp,
    const std::string &protocol, const std::string &eventType,
    const std::vector<ThreatMatch> &threatMatches,
    const std::vector<PolicyMatch> &policyMatches) {
  (void)timestamp;
  (void)domain;
  (void)sourceIp;
  (void)destinationIp;
  (void)protocol;
  (void)eventType;
  (void)threatMatches;
  (void)policyMatches;
}

#endif
