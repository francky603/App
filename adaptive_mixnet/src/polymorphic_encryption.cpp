/**
 * @file polymorphic_encryption.cpp
 * @brief Implementation of Polymorphic Encryption module
 */

#include "polymorphic_encryption.h"
#include <chrono>
#include <random>
#include <algorithm>
#include <stdexcept>

namespace AdaptiveMixnet {

PolymorphicEncryption::PolymorphicEncryption() 
    : current_algorithm_(EncryptionAlgorithm::XOR_CIPHER),
      current_key_(0),
      key_seed_(0) {
    stats_ = {};
}

PolymorphicEncryption::~PolymorphicEncryption() {}

void PolymorphicEncryption::initialize(uint32_t seed) {
    key_seed_ = seed;
    updateKey();
    stats_ = {};
}

uint32_t PolymorphicEncryption::generateKey() const {
    std::mt19937 gen(key_seed_);
    std::uniform_int_distribution<uint32_t> dist(1, 0xFFFFFFFF);
    return dist(gen);
}

void PolymorphicEncryption::updateKey() {
    current_key_ = generateKey();
}

std::vector<uint8_t> PolymorphicEncryption::xorEncrypt(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> result(data.size());
    uint8_t key_byte = static_cast<uint8_t>(current_key_ & 0xFF);
    
    for (size_t i = 0; i < data.size(); ++i) {
        result[i] = data[i] ^ (key_byte + static_cast<uint8_t>(i % 256));
    }
    
    return result;
}

std::vector<uint8_t> PolymorphicEncryption::xorDecrypt(const std::vector<uint8_t>& data) {
    return xorEncrypt(data); // XOR is symmetric
}

std::vector<uint8_t> PolymorphicEncryption::rotationEncrypt(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> result(data.size());
    uint8_t rotation = static_cast<uint8_t>(current_key_ % 8);
    
    for (size_t i = 0; i < data.size(); ++i) {
        uint8_t byte = data[i];
        result[i] = (byte << rotation) | (byte >> (8 - rotation));
    }
    
    return result;
}

std::vector<uint8_t> PolymorphicEncryption::rotationDecrypt(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> result(data.size());
    uint8_t rotation = static_cast<uint8_t>(current_key_ % 8);
    
    for (size_t i = 0; i < data.size(); ++i) {
        uint8_t byte = data[i];
        result[i] = (byte >> rotation) | (byte << (8 - rotation));
    }
    
    return result;
}

std::vector<uint8_t> PolymorphicEncryption::substitutionEncrypt(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> result(data.size());
    uint8_t shift = static_cast<uint8_t>(current_key_ % 256);
    
    for (size_t i = 0; i < data.size(); ++i) {
        result[i] = data[i] + shift;
    }
    
    return result;
}

std::vector<uint8_t> PolymorphicEncryption::substitutionDecrypt(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> result(data.size());
    uint8_t shift = static_cast<uint8_t>(current_key_ % 256);
    
    for (size_t i = 0; i < data.size(); ++i) {
        result[i] = data[i] - shift;
    }
    
    return result;
}

std::vector<uint8_t> PolymorphicEncryption::compositeEncrypt(const std::vector<uint8_t>& data) {
    auto step1 = xorEncrypt(data);
    auto step2 = rotationEncrypt(step1);
    auto step3 = substitutionEncrypt(step2);
    return step3;
}

std::vector<uint8_t> PolymorphicEncryption::compositeDecrypt(const std::vector<uint8_t>& data) {
    auto step1 = substitutionDecrypt(data);
    auto step2 = rotationDecrypt(step1);
    auto step3 = xorDecrypt(step2);
    return step3;
}

std::vector<uint8_t> PolymorphicEncryption::encrypt(const std::vector<uint8_t>& data,
                                                     EncryptionAlgorithm algo) {
    auto start = std::chrono::high_resolution_clock::now();
    
    std::vector<uint8_t> result;
    
    switch (algo) {
        case EncryptionAlgorithm::XOR_CIPHER:
            result = xorEncrypt(data);
            break;
        case EncryptionAlgorithm::ROTATION_CIPHER:
            result = rotationEncrypt(data);
            break;
        case EncryptionAlgorithm::SUBSTITUTION_CIPHER:
            result = substitutionEncrypt(data);
            break;
        case EncryptionAlgorithm::COMPOSITE_CIPHER:
            result = compositeEncrypt(data);
            break;
        default:
            throw std::invalid_argument("Unknown encryption algorithm");
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> elapsed = end - start;
    
    stats_.bytes_encrypted += data.size();
    stats_.avg_encryption_time_ms = (stats_.avg_encryption_time_ms * (stats_.bytes_encrypted - data.size()) 
                                     + elapsed.count()) / stats_.bytes_encrypted;
    
    return result;
}

std::vector<uint8_t> PolymorphicEncryption::decrypt(const std::vector<uint8_t>& data,
                                                     EncryptionAlgorithm algo) {
    auto start = std::chrono::high_resolution_clock::now();
    
    std::vector<uint8_t> result;
    
    switch (algo) {
        case EncryptionAlgorithm::XOR_CIPHER:
            result = xorDecrypt(data);
            break;
        case EncryptionAlgorithm::ROTATION_CIPHER:
            result = rotationDecrypt(data);
            break;
        case EncryptionAlgorithm::SUBSTITUTION_CIPHER:
            result = substitutionDecrypt(data);
            break;
        case EncryptionAlgorithm::COMPOSITE_CIPHER:
            result = compositeDecrypt(data);
            break;
        default:
            throw std::invalid_argument("Unknown encryption algorithm");
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double, std::milli> elapsed = end - start;
    
    stats_.bytes_decrypted += data.size();
    stats_.avg_decryption_time_ms = (stats_.avg_decryption_time_ms * (stats_.bytes_decrypted - data.size()) 
                                     + elapsed.count()) / stats_.bytes_decrypted;
    
    return result;
}

void PolymorphicEncryption::switchAlgorithm(EncryptionAlgorithm new_algo) {
    if (new_algo != current_algorithm_) {
        current_algorithm_ = new_algo;
        stats_.algorithm_switches++;
        updateKey();
    }
}

EncryptionAlgorithm PolymorphicEncryption::getCurrentAlgorithm() const {
    return current_algorithm_;
}

EncryptionAlgorithm PolymorphicEncryption::selectAlgorithmBasedOnThreat(double threat_level) {
    if (threat_level < 0.25) {
        return EncryptionAlgorithm::XOR_CIPHER;
    } else if (threat_level < 0.5) {
        return EncryptionAlgorithm::ROTATION_CIPHER;
    } else if (threat_level < 0.75) {
        return EncryptionAlgorithm::SUBSTITUTION_CIPHER;
    } else {
        return EncryptionAlgorithm::COMPOSITE_CIPHER;
    }
}

EncryptionStats PolymorphicEncryption::getStats() const {
    return stats_;
}

void PolymorphicEncryption::resetStats() {
    stats_ = {};
}

} // namespace AdaptiveMixnet
