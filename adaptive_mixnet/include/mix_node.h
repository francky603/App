/**
 * @file mix_node.h
 * @brief Mix Node header - represents a single node in the mixnet
 * 
 * Each mix node receives encrypted messages, shuffles them, and forwards
 * them to the next hop with adaptive behavior based on network conditions.
 */

#ifndef MIX_NODE_H
#define MIX_NODE_H

#include "polymorphic_encryption.h"
#include <vector>
#include <queue>
#include <string>
#include <mutex>
#include <atomic>
#include <functional>

namespace AdaptiveMixnet {

struct Message {
    std::vector<uint8_t> payload;
    std::string destination;
    uint32_t hop_count;
    uint64_t timestamp;
    double priority;
};

struct NodeConfig {
    std::string node_id;
    uint32_t max_queue_size;
    uint32_t batch_size;
    uint32_t flush_interval_ms;
    double threat_threshold;
    bool logging_enabled;
};

struct NodeStats {
    uint64_t messages_received;
    uint64_t messages_forwarded;
    uint64_t messages_dropped;
    uint64_t batches_processed;
    double avg_latency_ms;
    double current_threat_level;
    uint32_t algorithm_changes;
};

class MixNode {
public:
    explicit MixNode(const NodeConfig& config);
    ~MixNode();

    void initialize(uint32_t encryption_seed);
    
    bool receiveMessage(const Message& msg);
    std::vector<Message> processBatch();
    void flushQueue();
    
    void setThreatLevel(double level);
    double getThreatLevel() const;
    
    void setNextHopCallback(std::function<void(const std::vector<Message>&)> callback);
    
    NodeStats getStats() const;
    void resetStats();
    
    std::string getNodeId() const;
    bool isHealthy() const;

private:
    void shuffleMessages(std::vector<Message>& messages);
    void applyPadding(std::vector<Message>& messages);
    EncryptionAlgorithm determineEncryptionMethod();
    void updateAdaptiveParameters();
    
    NodeConfig config_;
    NodeStats stats_;
    
    std::queue<Message> message_queue_;
    mutable std::mutex queue_mutex_;
    
    PolymorphicEncryption encryption_;
    
    std::atomic<double> current_threat_level_;
    std::atomic<bool> is_healthy_;
    
    std::function<void(const std::vector<Message>&)> next_hop_callback_;
    
    uint32_t batch_counter_;
};

} // namespace AdaptiveMixnet

#endif // MIX_NODE_H
