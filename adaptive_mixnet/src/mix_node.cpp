/**
 * @file mix_node.cpp
 * @brief Implementation of Mix Node
 */

#include "mix_node.h"
#include <algorithm>
#include <random>
#include <chrono>
#include <iostream>

namespace AdaptiveMixnet {

MixNode::MixNode(const NodeConfig& config)
    : config_(config),
      current_threat_level_(0.0),
      is_healthy_(true),
      batch_counter_(0) {
    stats_ = {};
}

MixNode::~MixNode() {}

void MixNode::initialize(uint32_t encryption_seed) {
    encryption_.initialize(encryption_seed);
    stats_ = {};
    is_healthy_ = true;
}

bool MixNode::receiveMessage(const Message& msg) {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    
    if (message_queue_.size() >= config_.max_queue_size) {
        stats_.messages_dropped++;
        if (config_.logging_enabled) {
            std::cerr << "[" << config_.node_id << "] Queue full, dropping message\n";
        }
        return false;
    }
    
    message_queue_.push(msg);
    stats_.messages_received++;
    
    return true;
}

std::vector<Message> MixNode::processBatch() {
    std::lock_guard<std::mutex> lock(queue_mutex_);
    
    std::vector<Message> batch;
    uint32_t count = 0;
    
    while (!message_queue_.empty() && count < config_.batch_size) {
        batch.push_back(message_queue_.front());
        message_queue_.pop();
        count++;
    }
    
    if (batch.empty()) {
        return batch;
    }
    
    auto start_time = std::chrono::high_resolution_clock::now();
    
    shuffleMessages(batch);
    applyPadding(batch);
    
    EncryptionAlgorithm algo = determineEncryptionMethod();
    
    for (auto& msg : batch) {
        std::vector<uint8_t> encrypted = encryption_.encrypt(msg.payload, algo);
        msg.payload = encrypted;
        msg.hop_count++;
    }
    
    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> elapsed = end_time - start_time;
    
    stats_.batches_processed++;
    stats_.messages_forwarded += batch.size();
    
    double new_avg = (stats_.avg_latency_ms * (stats_.messages_forwarded - batch.size()) 
                      + elapsed.count() * batch.size()) / stats_.messages_forwarded;
    stats_.avg_latency_ms = new_avg;
    
    batch_counter_++;
    
    if (next_hop_callback_) {
        next_hop_callback_(batch);
    }
    
    return batch;
}

void MixNode::flushQueue() {
    while (!message_queue_.empty()) {
        processBatch();
    }
}

void MixNode::setThreatLevel(double level) {
    current_threat_level_ = std::max(0.0, std::min(1.0, level));
    stats_.current_threat_level = current_threat_level_.load();
    updateAdaptiveParameters();
}

double MixNode::getThreatLevel() const {
    return current_threat_level_.load();
}

void MixNode::setNextHopCallback(std::function<void(const std::vector<Message>&)> callback) {
    next_hop_callback_ = callback;
}

NodeStats MixNode::getStats() const {
    NodeStats result = stats_;
    result.current_threat_level = current_threat_level_.load();
    result.algorithm_changes = encryption_.getStats().algorithm_switches;
    return result;
}

void MixNode::resetStats() {
    stats_ = {};
    encryption_.resetStats();
}

std::string MixNode::getNodeId() const {
    return config_.node_id;
}

bool MixNode::isHealthy() const {
    return is_healthy_.load();
}

void MixNode::shuffleMessages(std::vector<Message>& messages) {
    static std::random_device rd;
    static std::mt19937 g(rd());
    
    std::shuffle(messages.begin(), messages.end(), g);
}

void MixNode::applyPadding(std::vector<Message>& messages) {
    size_t max_size = 0;
    for (const auto& msg : messages) {
        max_size = std::max(max_size, msg.payload.size());
    }
    
    for (auto& msg : messages) {
        while (msg.payload.size() < max_size) {
            msg.payload.push_back(0x00);
        }
    }
}

EncryptionAlgorithm MixNode::determineEncryptionMethod() {
    double threat = current_threat_level_.load();
    return encryption_.selectAlgorithmBasedOnThreat(threat);
}

void MixNode::updateAdaptiveParameters() {
    double threat = current_threat_level_.load();
    
    if (threat > config_.threat_threshold) {
        EncryptionAlgorithm new_algo = encryption_.selectAlgorithmBasedOnThreat(threat);
        if (new_algo != encryption_.getCurrentAlgorithm()) {
            encryption_.switchAlgorithm(new_algo);
            if (config_.logging_enabled) {
                std::cout << "[" << config_.node_id << "] Switched algorithm due to threat level: " 
                          << threat << "\n";
            }
        }
    }
    
    if (threat > 0.9) {
        is_healthy_ = false;
        if (config_.logging_enabled) {
            std::cerr << "[" << config_.node_id << "] Node unhealthy due to high threat\n";
        }
    } else {
        is_healthy_ = true;
    }
}

} // namespace AdaptiveMixnet
