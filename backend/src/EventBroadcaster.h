#pragma once

#include <cstdint>
#include <deque>
#include <mutex>
#include <string>
#include <vector>

class EventBroadcaster {
public:
    void addClient(int clientFd, std::uint64_t lastEventId = 0);
    void removeClient(int clientFd);
    void broadcast(const std::string &jsonPayload);

private:
    struct StreamEvent {
        std::uint64_t id;
        std::string payload;
    };

    bool sendMessage(int clientFd, const std::string &message);
    std::string buildMessage(std::uint64_t eventId, const std::string &jsonPayload) const;

    std::mutex clientsMutex;
    std::vector<int> clients;
    std::deque<StreamEvent> history;
    std::uint64_t nextEventId = 1;
};
