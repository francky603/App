/**
 * @file main.cpp
 * @brief Main demonstration program for Adaptive Mixnet with Polymorphic Encryption
 * 
 * This program demonstrates the adaptive mixnet system with:
 * - Polymorphic encryption that changes algorithms based on threat levels
 * - Multiple mix nodes that shuffle and forward messages
 * - Dynamic threat detection and response
 * - Network attack simulation and resistance
 */

#include "adaptive_mixnet.h"
#include <iostream>
#include <vector>
#include <chrono>
#include <thread>
#include <iomanip>

using namespace AdaptiveMixnet;

void demonstrateEncryption() {
    std::cout << "\n=== Polymorphic Encryption Demonstration ===\n\n";
    
    PolymorphicEncryption enc;
    enc.initialize(12345);
    
    std::vector<uint8_t> original_data = {'H', 'e', 'l', 'l', 'o', ',', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
    
    std::cout << "Original data: ";
    for (auto byte : original_data) {
        std::cout << static_cast<char>(byte);
    }
    std::cout << "\n\n";
    
    std::vector<EncryptionAlgorithm> algorithms = {
        EncryptionAlgorithm::XOR_CIPHER,
        EncryptionAlgorithm::ROTATION_CIPHER,
        EncryptionAlgorithm::SUBSTITUTION_CIPHER,
        EncryptionAlgorithm::COMPOSITE_CIPHER
    };
    
    std::vector<std::string> algo_names = {"XOR", "Rotation", "Substitution", "Composite"};
    
    for (size_t i = 0; i < algorithms.size(); ++i) {
        auto encrypted = enc.encrypt(original_data, algorithms[i]);
        auto decrypted = enc.decrypt(encrypted, algorithms[i]);
        
        std::cout << algo_names[i] << " Encryption:\n";
        std::cout << "  Encrypted bytes: ";
        for (auto byte : encrypted) {
            std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte) << " ";
        }
        std::cout << std::dec << "\n";
        std::cout << "  Decryption successful: " << (original_data == decrypted ? "YES" : "NO") << "\n\n";
    }
    
    auto stats = enc.getStats();
    std::cout << "Encryption Statistics:\n";
    std::cout << "  Bytes encrypted: " << stats.bytes_encrypted << "\n";
    std::cout << "  Bytes decrypted: " << stats.bytes_decrypted << "\n";
    std::cout << "  Algorithm switches: " << stats.algorithm_switches << "\n\n";
}

void demonstrateThreatAdaptation() {
    std::cout << "\n=== Threat-Based Algorithm Adaptation ===\n\n";
    
    PolymorphicEncryption enc;
    enc.initialize(54321);
    
    std::vector<double> threat_levels = {0.1, 0.3, 0.6, 0.85};
    
    std::cout << "Testing algorithm selection based on threat levels:\n\n";
    
    for (double threat : threat_levels) {
        auto selected_algo = enc.selectAlgorithmBasedOnThreat(threat);
        
        std::string algo_name;
        switch (selected_algo) {
            case EncryptionAlgorithm::XOR_CIPHER:
                algo_name = "XOR Cipher (Low overhead)";
                break;
            case EncryptionAlgorithm::ROTATION_CIPHER:
                algo_name = "Rotation Cipher (Medium overhead)";
                break;
            case EncryptionAlgorithm::SUBSTITUTION_CIPHER:
                algo_name = "Substitution Cipher (Higher security)";
                break;
            case EncryptionAlgorithm::COMPOSITE_CIPHER:
                algo_name = "Composite Cipher (Maximum security)";
                break;
        }
        
        std::cout << "  Threat Level: " << std::fixed << std::setprecision(2) << threat 
                  << " -> " << algo_name << "\n";
    }
    std::cout << "\n";
}

void demonstrateMixnet() {
    std::cout << "\n=== Adaptive Mixnet Network Demonstration ===\n\n";
    
    NetworkConfig config;
    config.num_nodes = 5;
    config.min_path_length = 2;
    config.max_path_length = 4;
    config.base_threat_level = 0.2;
    config.monitoring_interval_ms = 500;
    config.enable_logging = true;
    
    AdaptiveMixnet::AdaptiveMixnet mixnet(config);
    
    std::cout << "Initializing mixnet network...\n";
    mixnet.initialize();
    
    std::cout << "Starting network operations...\n";
    mixnet.start();
    
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    std::cout << "\nSending test messages through the network...\n\n";
    
    for (int i = 0; i < 10; ++i) {
        std::vector<uint8_t> payload;
        std::string message = "Message_" + std::to_string(i);
        for (char c : message) {
            payload.push_back(static_cast<uint8_t>(c));
        }
        
        bool success = mixnet.sendMessage(payload, "destination_" + std::to_string(i % 3));
        std::cout << "Sent message " << i << ": " << (success ? "SUCCESS" : "FAILED") << "\n";
        
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    mixnet.updateThreatAssessment();
    mixnet.printNetworkStatus();
    
    std::cout << "\nSimulating network attack (intensity: 0.7)...\n";
    mixnet.simulateAttack(0.7);
    
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    
    mixnet.updateThreatAssessment();
    mixnet.printNetworkStatus();
    
    std::cout << "\nSending more messages under attack conditions...\n\n";
    
    for (int i = 10; i < 15; ++i) {
        std::vector<uint8_t> payload;
        std::string message = "Message_" + std::to_string(i);
        for (char c : message) {
            payload.push_back(static_cast<uint8_t>(c));
        }
        
        bool success = mixnet.sendMessage(payload, "destination_" + std::to_string(i % 3));
        std::cout << "Sent message " << i << ": " << (success ? "SUCCESS" : "FAILED") << "\n";
        
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    
    mixnet.updateThreatAssessment();
    mixnet.printNetworkStatus();
    
    std::cout << "Stopping network...\n";
    mixnet.stop();
    
    auto final_stats = mixnet.getNetworkStats();
    std::cout << "\nFinal Network Statistics:\n";
    std::cout << "  Total messages sent: " << final_stats.total_messages_sent << "\n";
    std::cout << "  Total messages received: " << final_stats.total_messages_received << "\n";
    std::cout << "  Total messages lost: " << final_stats.total_messages_lost << "\n";
    std::cout << "  Active nodes: " << final_stats.active_nodes << "\n";
    std::cout << "  Average threat level: " << std::fixed << std::setprecision(2) 
              << final_stats.avg_threat_level << "\n";
    std::cout << "  Total algorithm switches: " << final_stats.total_algorithm_switches << "\n";
}

void demonstrateProactiveResistance() {
    std::cout << "\n=== Proactive Attack Resistance Demonstration ===\n\n";
    
    NetworkConfig config;
    config.num_nodes = 8;
    config.min_path_length = 3;
    config.max_path_length = 5;
    config.base_threat_level = 0.1;
    config.monitoring_interval_ms = 200;
    config.enable_logging = false;
    
    AdaptiveMixnet::AdaptiveMixnet mixnet(config);
    mixnet.initialize();
    mixnet.start();
    
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    std::cout << "Baseline network status:\n";
    mixnet.updateThreatAssessment();
    auto baseline_stats = mixnet.getNetworkStats();
    std::cout << "  Active nodes: " << baseline_stats.active_nodes << "\n";
    std::cout << "  Avg threat level: " << std::fixed << std::setprecision(2) 
              << baseline_stats.avg_threat_level << "\n\n";
    
    std::cout << "Simulating progressive attack scenarios:\n\n";
    
    std::vector<double> attack_intensities = {0.3, 0.5, 0.7, 0.9};
    
    for (double intensity : attack_intensities) {
        std::cout << "Attack intensity: " << std::fixed << std::setprecision(1) << intensity << "\n";
        
        mixnet.simulateAttack(intensity);
        std::this_thread::sleep_for(std::chrono::milliseconds(150));
        
        mixnet.updateThreatAssessment();
        auto stats = mixnet.getNetworkStats();
        
        std::cout << "  Active nodes: " << stats.active_nodes << "\n";
        std::cout << "  Avg threat level: " << std::fixed << std::setprecision(2) 
                  << stats.avg_threat_level << "\n";
        std::cout << "  Algorithm switches: " << stats.total_algorithm_switches << "\n";
        std::cout << "  Messages sent: " << stats.total_messages_sent << "\n\n";
    }
    
    mixnet.stop();
    
    std::cout << "Network demonstrated adaptive resistance to attacks by:\n";
    std::cout << "  1. Switching to stronger encryption algorithms under threat\n";
    std::cout << "  2. Dynamically routing around compromised nodes\n";
    std::cout << "  3. Maintaining operation despite partial node degradation\n";
    std::cout << "  4. Real-time threat assessment and response\n\n";
}

int main() {
    std::cout << "╔═══════════════════════════════════════════════════════════╗\n";
    std::cout << "║  Adaptive Mixnet with Polymorphic Encryption             ║\n";
    std::cout << "║  Proactive Resistance to Network Attacks                 ║\n";
    std::cout << "╚═══════════════════════════════════════════════════════════╝\n\n";
    
    try {
        demonstrateEncryption();
        demonstrateThreatAdaptation();
        demonstrateMixnet();
        demonstrateProactiveResistance();
        
        std::cout << "\n╔═══════════════════════════════════════════════════════════╗\n";
        std::cout << "║  Demonstration Complete                                  ║\n";
        std::cout << "╚═══════════════════════════════════════════════════════════╝\n";
        
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 1;
    }
}
