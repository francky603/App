#ifndef CRYPTO_PQC_H
#define CRYPTO_PQC_H

#include <vector>
#include <array>
#include <string>
#include <random>
#include <memory>
#include <cstdint>

namespace pqmix {

// Constantes pour les tailles de clés PQC (simulées pour compatibilité liboqs)
constexpr size_t ML_KEM_768_PUBLIC_KEY_SIZE = 1088;
constexpr size_t ML_KEM_768_SECRET_KEY_SIZE = 2400;
constexpr size_t ML_KEM_768_CIPHERTEXT_SIZE = 1088;
constexpr size_t ML_KEM_768_SHARED_SECRET_SIZE = 32;

constexpr size_t X25519_KEY_SIZE = 32;
constexpr size_t AES_256_KEY_SIZE = 32;
constexpr size_t AES_GCM_NONCE_SIZE = 12;
constexpr size_t AES_GCM_TAG_SIZE = 16;

constexpr size_t ML_DSA_PUBLIC_KEY_SIZE = 2592;
constexpr size_t ML_DSA_SECRET_KEY_SIZE = 4864;
constexpr size_t ML_DSA_SIGNATURE_SIZE = 4595;

/**
 * @brief Simulation d'opérations ML-KEM (Kyber) pour l'échange de clés post-quantique
 * En production, utiliser liboqs (https://github.com/open-quantum-safe/liboqs)
 */
class MLKEM {
public:
    struct KeyPair {
        std::array<uint8_t, ML_KEM_768_PUBLIC_KEY_SIZE> public_key;
        std::array<uint8_t, ML_KEM_768_SECRET_KEY_SIZE> secret_key;
    };

    static KeyPair generate_keypair(std::mt19937_64& rng);
    
    struct EncapsulationResult {
        std::array<uint8_t, ML_KEM_768_CIPHERTEXT_SIZE> ciphertext;
        std::array<uint8_t, ML_KEM_768_SHARED_SECRET_SIZE> shared_secret;
    };

    static EncapsulationResult encapsulate(const std::array<uint8_t, ML_KEM_768_PUBLIC_KEY_SIZE>& public_key, 
                                           std::mt19937_64& rng);
    
    static std::array<uint8_t, ML_KEM_768_SHARED_SECRET_SIZE> decapsulate(
        const std::array<uint8_t, ML_KEM_768_CIPHERTEXT_SIZE>& ciphertext,
        const std::array<uint8_t, ML_KEM_768_SECRET_KEY_SIZE>& secret_key);
};

/**
 * @brief Échange de clés X25519 (Curve25519) pour le mode hybride
 */
class X25519 {
public:
    using PublicKey = std::array<uint8_t, X25519_KEY_SIZE>;
    using PrivateKey = std::array<uint8_t, X25519_KEY_SIZE>;
    using SharedSecret = std::array<uint8_t, X25519_KEY_SIZE>;

    static std::pair<PrivateKey, PublicKey> generate_keypair(std::mt19937_64& rng);
    static SharedSecret dh(const PrivateKey& private_key, const PublicKey& other_public);
};

/**
 * @brief ML-DSA (Dilithium) pour les signatures post-quantiques
 */
class MLDSA {
public:
    struct KeyPair {
        std::array<uint8_t, ML_DSA_PUBLIC_KEY_SIZE> public_key;
        std::array<uint8_t, ML_DSA_SECRET_KEY_SIZE> secret_key;
    };

    static KeyPair generate_keypair(std::mt19937_64& rng);
    static std::array<uint8_t, ML_DSA_SIGNATURE_SIZE> sign(
        const std::vector<uint8_t>& message,
        const std::array<uint8_t, ML_DSA_SECRET_KEY_SIZE>& secret_key,
        std::mt19937_64& rng);
    
    static bool verify(const std::vector<uint8_t>& message,
                       const std::array<uint8_t, ML_DSA_SIGNATURE_SIZE>& signature,
                       const std::array<uint8_t, ML_DSA_PUBLIC_KEY_SIZE>& public_key);
};

/**
 * @brief AES-256-GCM pour le chiffrement symétrique AEAD
 */
class AES256GCM {
public:
    static std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext,
                                        const std::array<uint8_t, AES_256_KEY_SIZE>& key,
                                        const std::array<uint8_t, AES_GCM_NONCE_SIZE>& nonce,
                                        const std::vector<uint8_t>& aad = {});
    
    static std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext,
                                        const std::array<uint8_t, AES_256_KEY_SIZE>& key,
                                        const std::array<uint8_t, AES_GCM_NONCE_SIZE>& nonce,
                                        const std::vector<uint8_t>& aad = {});
};

/**
 * @brief Générateur de dérivation de clé (HKDF-SHA256 simulé)
 */
class KDF {
public:
    static std::vector<uint8_t> derive(const std::vector<uint8_t>& ikm,
                                       const std::string& salt,
                                       const std::string& info,
                                       size_t length);
};

/**
 * @brief Suite cryptographique hybride (ML-KEM + X25519 + AES-256-GCM)
 * Conforme aux exigences: OID Kyber 0x6399, paquets > 2000 octets
 */
class HybridPQSuite {
public:
    struct SessionKeys {
        std::array<uint8_t, AES_256_KEY_SIZE> encryption_key;
        std::array<uint8_t, AES_GCM_NONCE_SIZE> nonce;
        uint64_t sequence_number;
    };

    // Côté serveur (récepteur du KEM)
    struct ServerHandshake {
        MLKEM::KeyPair ml_kem_keys;
        std::pair<X25519::PrivateKey, X25519::PublicKey> x25519_keys;
        std::array<uint8_t, ML_DSA_SIGNATURE_SIZE> signature;
        
        std::vector<uint8_t> serialize() const;
        static ServerHandshake deserialize(const std::vector<uint8_t>& data);
    };

    // Côté client (initiateur)
    struct ClientHandshake {
        std::array<uint8_t, ML_KEM_768_CIPHERTEXT_SIZE> ml_kem_ciphertext;
        X25519::PublicKey x25519_public;
        std::vector<uint8_t> certificate_chain; // Simulé
        
        std::vector<uint8_t> serialize() const;
        static ClientHandshake deserialize(const std::vector<uint8_t>& data);
    };

    static std::pair<ClientHandshake, SessionKeys> client_init(std::mt19937_64& rng);
    static SessionKeys server_complete(const ClientHandshake& client_hs,
                                       ServerHandshake& server_hs,
                                       std::mt19937_64& rng);
    
    // Rotation des clés (< 10 minutes aléatoire)
    static SessionKeys rotate_keys(const SessionKeys& current, std::mt19937_64& rng);
};

} // namespace pqmix

#endif // CRYPTO_PQC_H
