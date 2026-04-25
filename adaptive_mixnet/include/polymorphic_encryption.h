/**
 * @file polymorphic_encryption.h
 * @brief Polymorphic Encryption module header
 * 
 * This module implements polymorphic encryption where the encryption algorithm
 * changes dynamically based on network conditions and threat levels.
 */

#ifndef POLYMORPHIC_ENCRYPTION_H
#define POLYMORPHIC_ENCRYPTION_H

#include <vector>
#include <cstdint>
#include <string>
#include <functional>

namespace AdaptiveMixnet {

enum class EncryptionAlgorithm {
    XOR_CIPHER,
    ROTATION_CIPHER,
    SUBSTITUTION_CIPHER,
    COMPOSITE_CIPHER
};

struct EncryptionStats {
    uint64_t bytes_encrypted;
    uint64_t bytes_decrypted;
    uint32_t algorithm_switches;
    double avg_encryption_time_ms;
    double avg_decryption_time_ms;
};

class PolymorphicEncryption {
public:
    PolymorphicEncryption();
    ~PolymorphicEncryption();

    void initialize(uint32_t seed);
    
    std::vector<uint8_t> encrypt(const std::vector<uint8_t>& data, 
                                  EncryptionAlgorithm algo);
    std::vector<uint8_t> decrypt(const std::vector<uint8_t>& data, 
                                  EncryptionAlgorithm algo);
    
    void switchAlgorithm(EncryptionAlgorithm new_algo);
    EncryptionAlgorithm getCurrentAlgorithm() const;
    
    EncryptionAlgorithm selectAlgorithmBasedOnThreat(double threat_level);
    
    EncryptionStats getStats() const;
    void resetStats();

private:
    std::vector<uint8_t> xorEncrypt(const std::vector<uint8_t>& data);
    std::vector<uint8_t> rotationEncrypt(const std::vector<uint8_t>& data);
    std::vector<uint8_t> substitutionEncrypt(const std::vector<uint8_t>& data);
    std::vector<uint8_t> compositeEncrypt(const std::vector<uint8_t>& data);
    
    std::vector<uint8_t> xorDecrypt(const std::vector<uint8_t>& data);
    std::vector<uint8_t> rotationDecrypt(const std::vector<uint8_t>& data);
    std::vector<uint8_t> substitutionDecrypt(const std::vector<uint8_t>& data);
    std::vector<uint8_t> compositeDecrypt(const std::vector<uint8_t>& data);

    uint32_t generateKey() const;
    void updateKey();

    EncryptionAlgorithm current_algorithm_;
    uint32_t current_key_;
    uint32_t key_seed_;
    mutable EncryptionStats stats_;
    
    std::function<std::vector<uint8_t>(const std::vector<uint8_t>&)> encrypt_func_;
    std::function<std::vector<uint8_t>(const std::vector<uint8_t>&)> decrypt_func_;
};

} // namespace AdaptiveMixnet

#endif // POLYMORPHIC_ENCRYPTION_H
