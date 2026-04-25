/**
 * @file adaptive_mixnet.cpp
 * @brief Implementation of the main Adaptive Mixnet system
 */

#include "adaptive_mixnet.h"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace AdaptiveMixnet {

AdaptiveMixnet::AdaptiveMixnet(const NetworkConfig& config)
    : config_(config),
      running_(false),
      random_generator_(std::random_device{}()),
      message_counter_(0) {
    stats_ = {};
}

AdaptiveMixnet::~AdaptiveMixnet() {
    stop();
}

void AdaptiveMixnet::initialize() {
    std::lock_guard<std::mutex> lock(network_mutex_);
    
    nodes_.clear();
    incoming_buffers_.clear();
    
    for (uint32_t i = 0; i < config_.num_nodes; ++i) {
        NodeConfig node_config;
        std::ostringstream oss;
        oss << "node_" << std::setfill('0') << std::setw(2) << i;
        node_config.node_id = oss.str();
        node_config.max_queue_size = 1000;
        node_config.batch_size = 10;
        node_config.flush_interval_ms = 100;
        node_config.threat_threshold = 0.5;
        node_config.logging_enabled = config_.enable_logging;
        
        auto node = std::make_unique<MixNode>(node_config);
        node->initialize(i * 12345 + 42);
        
        nodes_[node_config.node_id] = std::move(node);
        incoming_buffers_[node_config.node_id] = std::vector<Message>();
    }
    
    if (config_.enable_logging) {
        std::cout << "Initialized mixnet with " << config_.num_nodes << " nodes\n";
    }
    
    stats_ = {};
}

void AdaptiveMixnet::start() {
    if (running_) return;
    
    running_ = true;
    monitoring_thread_ = std::thread(&AdaptiveMixnet::monitoringThread, this);
    
    if (config_.enable_logging) {
        std::cout << "Adaptive Mixnet started\n";
    }
}

void AdaptiveMixnet::stop() {
    if (!running_) return;
    
    running_ = false;
    
    if (monitoring_thread_.joinable()) {
        monitoring_thread_.join();
    }
    
    for (auto& pair : nodes_) {
        pair.second->flushQueue();
    }
    
    if (config_.enable_logging) {
        std::cout << "Adaptive Mixnet stopped\n";
    }
}

bool AdaptiveMixnet::sendMessage(const std::vector<uint8_t>& payload, const std::string& destination) {
    std::lock_guard<std::mutex> lock(network_mutex_);
    
    if (nodes_.empty()) {
        return false;
    }
    
    std::vector<std::string> path = selectPath(destination);
    
    if (path.empty()) {
        return false;
    }
    
    Message msg;
    msg.payload = payload;
    msg.destination = destination;
    msg.hop_count = 0;
    msg.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    msg.priority = 1.0;
    
    auto encrypt_func = [this](const std::vector<Message>& messages, const std::string& next_node) {
        if (incoming_buffers_.find(next_node) != incoming_buffers_.end()) {
            for (const auto& msg : messages) {
                incoming_buffers_[next_node].push_back(msg);
            }
        }
    };
    
    std::string current_node = path[0];
    
    for (size_t i = 0; i < path.size() - 1; ++i) {
        std::string next_node = path[i + 1];
        
        auto callback = [&, next_node](const std::vector<Message>& msgs) {
            encrypt_func(msgs, next_node);
        };
        
        nodes_[current_node]->setNextHopCallback(callback);
        
        if (!nodes_[current_node]->receiveMessage(msg)) {
            stats_.total_messages_lost++;
            return false;
        }
        
        auto batch = nodes_[current_node]->processBatch();
        
        if (!batch.empty()) {
            msg = batch[0];
        }
        
        current_node = next_node;
    }
    
    stats_.total_messages_sent++;
    
    return true;
}

std::vector<Message> AdaptiveMixnet::receiveMessages(const std::string& node_id) {
    std::lock_guard<std::mutex> lock(network_mutex_);
    
    auto it = incoming_buffers_.find(node_id);
    if (it == incoming_buffers_.end()) {
        return {};
    }
    
    std::vector<Message> result = it->second;
    it->second.clear();
    
    stats_.total_messages_received += result.size();
    
    return result;
}

void AdaptiveMixnet::simulateAttack(double intensity, const std::string& target_node) {
    std::lock_guard<std::mutex> lock(network_mutex_);
    
    if (target_node.empty()) {
        for (auto& pair : nodes_) {
            double threat = std::min(1.0, pair.second->getThreatLevel() + intensity * 0.1);
            pair.second->setThreatLevel(threat);
        }
    } else {
        auto it = nodes_.find(target_node);
        if (it != nodes_.end()) {
            double threat = std::min(1.0, it->second->getThreatLevel() + intensity * 0.1);
            it->second->setThreatLevel(threat);
        }
    }
    
    if (config_.enable_logging) {
        std::cout << "Simulated attack with intensity " << intensity 
                  << (target_node.empty() ? " on all nodes" : " on " + target_node) << "\n";
    }
}

void AdaptiveMixnet::updateThreatAssessment() {
    std::lock_guard<std::mutex> lock(network_mutex_);
    
    double total_threat = 0.0;
    uint32_t active_count = 0;
    uint32_t total_switches = 0;
    
    for (auto& pair : nodes_) {
        if (pair.second->isHealthy()) {
            active_count++;
            total_threat += pair.second->getThreatLevel();
            total_switches += pair.second->getStats().algorithm_changes;
        }
    }
    
    stats_.avg_threat_level = active_count > 0 ? total_threat / active_count : 0.0;
    stats_.active_nodes = active_count;
    stats_.total_algorithm_switches = total_switches;
}

NetworkStats AdaptiveMixnet::getNetworkStats() const {
    NetworkStats result = stats_;
    
    uint32_t active_count = 0;
    for (const auto& pair : nodes_) {
        if (pair.second->isHealthy()) {
            active_count++;
        }
    }
    result.active_nodes = active_count;
    
    return result;
}

NodeStats AdaptiveMixnet::getNodeStats(const std::string& node_id) const {
    auto it = nodes_.find(node_id);
    if (it == nodes_.end()) {
        return {};
    }
    return it->second->getStats();
}

std::vector<std::string> AdaptiveMixnet::getActiveNodes() const {
    std::vector<std::string> active;
    for (const auto& pair : nodes_) {
        if (pair.second->isHealthy()) {
            active.push_back(pair.first);
        }
    }
    return active;
}

void AdaptiveMixnet::printNetworkStatus() const {
    std::cout << "\n=== Adaptive Mixnet Status ===\n";
    std::cout << "Total Nodes: " << config_.num_nodes << "\n";
    
    uint32_t active = 0;
    for (const auto& pair : nodes_) {
        if (pair.second->isHealthy()) active++;
    }
    std::cout << "Active Nodes: " << active << "\n";
    
    std::cout << "Messages Sent: " << stats_.total_messages_sent << "\n";
    std::cout << "Messages Received: " << stats_.total_messages_received << "\n";
    std::cout << "Messages Lost: " << stats_.total_messages_lost << "\n";
    std::cout << "Avg Threat Level: " << std::fixed << std::setprecision(2) 
              << stats_.avg_threat_level << "\n";
    std::cout << "Algorithm Switches: " << stats_.total_algorithm_switches << "\n";
    
    std::cout << "\nNode Details:\n";
    for (const auto& pair : nodes_) {
        auto node_stats = pair.second->getStats();
        std::cout << "  " << pair.first << ": "
                  << "Health=" << (pair.second->isHealthy() ? "OK" : "DEGRADED")
                  << ", Threat=" << std::fixed << std::setprecision(2) << node_stats.current_threat_level
                  << ", Msgs=" << node_stats.messages_forwarded
                  << ", AlgoChanges=" << node_stats.algorithm_changes << "\n";
    }
    std::cout << "==============================\n\n";
}

std::vector<std::string> AdaptiveMixnet::selectPath(const std::string& destination) {
    std::vector<std::string> path;
    
    std::vector<std::string> active_nodes;
    for (const auto& pair : nodes_) {
        if (pair.second->isHealthy()) {
            active_nodes.push_back(pair.first);
        }
    }
    
    if (active_nodes.empty()) {
        return path;
    }
    
    uint32_t path_length = config_.min_path_length;
    if (config_.max_path_length > config_.min_path_length) {
        std::uniform_int_distribution<uint32_t> dist(
            config_.min_path_length, config_.max_path_length);
        path_length = dist(random_generator_);
    }
    
    path_length = std::min(path_length, static_cast<uint32_t>(active_nodes.size()));
    
    std::shuffle(active_nodes.begin(), active_nodes.end(), random_generator_);
    
    for (uint32_t i = 0; i < path_length && i < active_nodes.size(); ++i) {
        path.push_back(active_nodes[i]);
    }
    
    return path;
}

void AdaptiveMixnet::monitoringThread() {
    while (running_) {
        updateThreatAssessment();
        
        std::this_thread::sleep_for(std::chrono::milliseconds(config_.monitoring_interval_ms));
    }
}

void AdaptiveMixnet::processIncomingMessage(const std::string& node_id, 
                                             const std::vector<Message>& messages) {
    std::lock_guard<std::mutex> lock(network_mutex_);
    
    auto it = incoming_buffers_.find(node_id);
    if (it != incoming_buffers_.end()) {
        for (const auto& msg : messages) {
            it->second.push_back(msg);
        }
    }
}

} // namespace AdaptiveMixnet
