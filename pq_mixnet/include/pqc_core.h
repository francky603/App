#ifndef PQC_CORE_H
#define PQC_CORE_H

#include <vector>
#include <array>
#include <string>
#include <random>
#include <chrono>
#include <cstring>
#include <algorithm>
#include <stdexcept>

namespace pq_mixnet {

// Constantes pour ML-KEM-768 (Kyber)
constexpr size_t ML_KEM_PUBLIC_KEY_SIZE = 1184;
constexpr size_t ML_KEM_SECRET_KEY_SIZE = 2400;
constexpr size_t ML_KEM_CIPHERTEXT_SIZE = 1088;
constexpr size_t ML_KEM_SHARED_SECRET_SIZE = 32;

// Constantes pour ML-DSA (Dilithium)
constexpr size_t ML_DSA_PUBLIC_KEY_SIZE = 1312;
constexpr size_t ML_DSA_SECRET_KEY_SIZE = 2528;
constexpr size_t ML_DSA_SIGNATURE_SIZE = 2420;

// Constantes pour X25519
constexpr size_t X25519_KEY_SIZE = 32;

// Structure pour les clés hybrides
struct HybridKeyPair {
    std::array<uint8_t, X25519_KEY_SIZE> x25519_public;
    std::array<uint8_t, X25519_KEY_SIZE> x25519_private;
    std::array<uint8_t, ML_KEM_PUBLIC_KEY_SIZE> ml_kem_public;
    std::array<uint8_t, ML_KEM_SECRET_KEY_SIZE> ml_kem_private;
};

struct HybridCiphertext {
    std::array<uint8_t, X25519_KEY_SIZE> x25519_part;
    std::array<uint8_t, ML_KEM_CIPHERTEXT_SIZE> ml_kem_part;
};

class PqcCore {
public:
    PqcCore();
    
    // Génération de clés hybrides (X25519 + ML-KEM)
    HybridKeyPair generateHybridKeyPair();
    
    // Encapsulation hybride
    std::pair<HybridCiphertext, std::array<uint8_t, 64>> encapsulate(const HybridKeyPair& public_key);
    
    // Décapsulation hybride
    std::array<uint8_t, 64> decapsulate(const HybridCiphertext& ciphertext, const HybridKeyPair& private_key);
    
    // Signature ML-DSA (simulation sécurisée)
    std::vector<uint8_t> sign(const std::vector<uint8_t>& message, const std::array<uint8_t, ML_DSA_SECRET_KEY_SIZE>& private_key);
    
    // Vérification de signature
    bool verify(const std::vector<uint8_t>& message, const std::vector<uint8_t>& signature, 
                const std::array<uint8_t, ML_DSA_PUBLIC_KEY_SIZE>& public_key);
    
    // Dérivation de clé partagée finale (SHA3-256 simulé)
    std::array<uint8_t, 32> deriveSharedKey(const std::array<uint8_t, 64>& combined_secret);
    
    // Hash SHA3-256 simplifié (simulation) - public pour VRF
    std::array<uint8_t, 32> sha3_256(const uint8_t* data, size_t len);
    
    // Rotation de clés (génération nouvelle paire)
    void rotateKeys(HybridKeyPair& keys);

private:
    std::mt19937_64 rng_;
    
    // Simulation cryptographique sécurisée (pour démonstration)
    void simulateX25519KeyGen(std::array<uint8_t, 32>& pub, std::array<uint8_t, 32>& priv);
    void simulateMLKemKeyGen(std::array<uint8_t, ML_KEM_PUBLIC_KEY_SIZE>& pub, 
                             std::array<uint8_t, ML_KEM_SECRET_KEY_SIZE>& priv);
    void simulateMLKemEncaps(const std::array<uint8_t, ML_KEM_PUBLIC_KEY_SIZE>& pub,
                            std::array<uint8_t, ML_KEM_CIPHERTEXT_SIZE>& ct,
                            std::array<uint8_t, 32>& shared);
    void simulateMLDsaSign(const std::vector<uint8_t>& msg, 
                          const std::array<uint8_t, ML_DSA_SECRET_KEY_SIZE>& priv,
                          std::vector<uint8_t>& sig);
};

} // namespace pq_mixnet

#endif // PQC_CORE_H
