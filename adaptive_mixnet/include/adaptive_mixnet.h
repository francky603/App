/**
 * @file adaptive_mixnet.h
 * @brief Main Adaptive Mixnet system header
 * 
 * This module orchestrates the entire mixnet network with multiple nodes,
 * adaptive threat detection, and dynamic routing capabilities.
 */

#ifndef ADAPTIVE_MIXNET_H
#define ADAPTIVE_MIXNET_H

#include "mix_node.h"
#include <memory>
#include <map>
#include <thread>
#include <condition_variable>
#include <random>

namespace AdaptiveMixnet {

struct NetworkConfig {
    uint32_t num_nodes;
    uint32_t min_path_length;
    uint32_t max_path_length;
    double base_threat_level;
    uint32_t monitoring_interval_ms;
    bool enable_logging;
};

struct NetworkStats {
    uint64_t total_messages_sent;
    uint64_t total_messages_received;
    uint64_t total_messages_lost;
    double avg_end_to_end_latency_ms;
    double network_throughput_msgs_per_sec;
    double avg_threat_level;
    uint32_t active_nodes;
    uint32_t total_algorithm_switches;
};

class AdaptiveMixnet {
public:
    explicit AdaptiveMixnet(const NetworkConfig& config);
    ~AdaptiveMixnet();

    void initialize();
    void start();
    void stop();
    
    bool sendMessage(const std::vector<uint8_t>& payload, const std::string& destination);
    std::vector<Message> receiveMessages(const std::string& node_id);
    
    void simulateAttack(double intensity, const std::string& target_node = "");
    void updateThreatAssessment();
    
    NetworkStats getNetworkStats() const;
    NodeStats getNodeStats(const std::string& node_id) const;
    std::vector<std::string> getActiveNodes() const;
    
    void printNetworkStatus() const;

private:
    std::vector<std::string> selectPath(const std::string& destination);
    void monitoringThread();
    void processIncomingMessage(const std::string& node_id, const std::vector<Message>& messages);
    
    NetworkConfig config_;
    NetworkStats stats_;
    
    std::map<std::string, std::unique_ptr<MixNode>> nodes_;
    std::map<std::string, std::vector<Message>> incoming_buffers_;
    
    std::thread monitoring_thread_;
    std::atomic<bool> running_;
    std::mutex network_mutex_;
    
    std::mt19937 random_generator_;
    uint32_t message_counter_;
};

} // namespace AdaptiveMixnet

#endif // ADAPTIVE_MIXNET_H
