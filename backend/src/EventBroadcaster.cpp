#include "EventBroadcaster.h"

#include <algorithm>
#include <iostream>
#include <sys/socket.h>
#include <unistd.h>

namespace {
constexpr std::size_t kMaxHistorySize = 2048;
}

std::string EventBroadcaster::buildMessage(std::uint64_t eventId, const std::string &jsonPayload) const {
    return "id: " + std::to_string(eventId) + "\n" +
           "event: sentinel\n" +
           "data: " + jsonPayload + "\n\n";
}

bool EventBroadcaster::sendMessage(int clientFd, const std::string &message) {
    const char *buffer = message.c_str();
    std::size_t remaining = message.size();
    while (remaining > 0) {
        const ssize_t sent = send(clientFd, buffer, remaining, 0);
        if (sent <= 0) {
            return false;
        }
        buffer += sent;
        remaining -= static_cast<std::size_t>(sent);
    }
    return true;
}

void EventBroadcaster::addClient(int clientFd, std::uint64_t lastEventId) {
    std::vector<std::string> replayMessages;
    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        clients.push_back(clientFd);

        if (lastEventId > 0) {
            for (const auto &event : history) {
                if (event.id > lastEventId) {
                    replayMessages.push_back(buildMessage(event.id, event.payload));
                }
            }
        }
    }

    std::cerr << "[WS] Client connected\n";

    for (const auto &message : replayMessages) {
        if (!sendMessage(clientFd, message)) {
            removeClient(clientFd);
            close(clientFd);
            return;
        }
    }
}

void EventBroadcaster::removeClient(int clientFd) {
    std::lock_guard<std::mutex> lock(clientsMutex);
    const auto oldSize = clients.size();
    clients.erase(std::remove(clients.begin(), clients.end(), clientFd), clients.end());
    if (clients.size() != oldSize) {
        std::cerr << "[WS] Client disconnected\n";
    }
}

void EventBroadcaster::broadcast(const std::string &jsonPayload) {
    std::vector<int> failedClients;
    std::string message;

    {
        std::lock_guard<std::mutex> lock(clientsMutex);
        const std::uint64_t eventId = nextEventId++;
        history.push_back({eventId, jsonPayload});
        if (history.size() > kMaxHistorySize) {
            history.pop_front();
        }
        message = buildMessage(eventId, jsonPayload);

        for (int clientFd : clients) {
            if (!sendMessage(clientFd, message)) {
                failedClients.push_back(clientFd);
            }
        }
    }

    for (int clientFd : failedClients) {
        removeClient(clientFd);
        close(clientFd);
    }

    std::cerr << "[WS] Event broadcasted\n";
}
