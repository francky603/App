/**
 * @file crypto_types.h
 * @brief Types cryptographiques communs pour le Mixnet Post-Quantique
 * 
 * Définition des structures de données, constantes et types utilisés
 * dans toutes les suites cryptographiques.
 */

#ifndef CRYPTO_TYPES_H
#define CRYPTO_TYPES_H

#include <cstdint>
#include <array>
#include <vector>
#include <string>
#include <memory>
#include <optional>

namespace mixnet {
namespace crypto {

// ============================================================================
// Constantes Cryptographiques
// ============================================================================

constexpr size_t AES_256_KEY_SIZE = 32;
constexpr size_t AES_GCM_NONCE_SIZE = 12;
constexpr size_t AES_GCM_TAG_SIZE = 16;
constexpr size_t XCHACHA20_NONCE_SIZE = 24;
constexpr size_t POLY1305_TAG_SIZE = 16;
constexpr size_t X25519_KEY_SIZE = 32;
constexpr size_t X25519_PUBLIC_SIZE = 32;
constexpr size_t RSA_2048_MODULUS_SIZE = 256;
constexpr size_t RSA_2048_KEY_SIZE = 2048;
constexpr size_t SHA256_HASH_SIZE = 32;
constexpr size_t ML_KEM_SECRET_SIZE = 32;
constexpr size_t ML_KEM_CIPHERTEXT_SIZE = 1088;
constexpr size_t FRODO_KEM_SECRET_SIZE = 32;
constexpr size_t FRODO_KEM_CIPHERTEXT_SIZE = 1152;
constexpr size_t SHARED_SECRET_SIZE = 32;

// ============================================================================
// Énumérations
// ============================================================================

/**
 * @brief Identifiants des suites cryptographiques supportées
 */
enum class CryptoSuiteID : uint8_t {
    RSA_AES_GCM = 0,              // Suite 1: RSA + AES-256-GCM
    X25519_AES_GCM = 1,           // Suite 2: X25519 + AES-256-GCM
    XCHACHA20_POLY1305 = 2,       // Suite 3: XChaCha20 + Poly1305
    AEGIS_X25519 = 3,             // Suite 4: AEGIS + X25519
    HYBRID_X25519_RSA = 4,        // Suite 5: Hybride X25519+RSA
    ML_KEM_AES_GCM = 5,           // Suite 6: ML-KEM (PQC) + AES-256-GCM
    FRODO_KEM_X25519 = 6,         // Suite 7: FrodoKEM + X25519
    AES_GCM_SIV_FRODO = 7,        // Suite 8: AES-GCM-SIV + FrodoKEM
    ML_DSA_X25519 = 8,            // Suite 9: ML-DSA + X25519
    INVALID = 255
};

/**
 * @brief Types de messages du protocole
 */
enum class MessageType : uint8_t {
    HELLO = 0,
    HELLO_ACK = 1,
    KEY_EXCHANGE = 2,
    AUTH = 3,
    AUTH_ACK = 4,
    MESSAGE = 5,
    RENEGOTIATE = 6,
    RENEGOTIATE_ACK = 7,
    PING = 8,
    PONG = 9,
    FILE_TRANSFER = 10,
    BLOCKCHAIN_ENTRY = 11,
    ERROR = 255
};

/**
 * @brief États de la session
 */
enum class SessionState : uint8_t {
    DISCONNECTED = 0,
    HANDSHAKE_INIT,
    KEY_EXCHANGE_PENDING,
    AUTHENTICATING,
    AUTHENTICATED,
    COMMUNICATING,
    RENEGOTIATING,
    CLOSED
};

// ============================================================================
// Structures de Données
// ============================================================================

/**
 * @brief Clé symétrique AES-256
 */
struct SymmetricKey {
    std::array<uint8_t, AES_256_KEY_SIZE> data;
    
    SymmetricKey() { data.fill(0); }
    explicit SymmetricKey(const std::array<uint8_t, AES_256_KEY_SIZE>& key) 
        : data(key) {}
    
    const uint8_t* data_ptr() const { return data.data(); }
    uint8_t* data_ptr() { return data.data(); }
    size_t size() const { return AES_256_KEY_SIZE; }
};

/**
 * @brief Nonce pour chiffrement AEAD
 */
struct Nonce {
    std::vector<uint8_t> data;
    
    Nonce() = default;
    explicit Nonce(size_t size) : data(size, 0) {}
    
    uint8_t* data_ptr() { return data.data(); }
    const uint8_t* data_ptr() const { return data.data(); }
    size_t size() const { return data.size(); }
};

/**
 * @brief Tag d'authentification AEAD
 */
struct AuthTag {
    std::array<uint8_t, 16> data;
    
    AuthTag() { data.fill(0); }
    
    uint8_t* data_ptr() { return data.data(); }
    const uint8_t* data_ptr() const { return data.data(); }
};

/**
 * @brief Résultat d'un échange de clés (KEM/EC DH)
 */
struct KeyExchangeResult {
    std::vector<uint8_t> public_key;
    std::vector<uint8_t> ciphertext;  // Pour KEM
    std::array<uint8_t, SHARED_SECRET_SIZE> shared_secret;
    bool success;
    std::string error_message;
    
    KeyExchangeResult() : success(false) {}
};

/**
 * @brief Résultat de chiffrement AEAD
 */
struct AEADCiphertext {
    Nonce nonce;
    std::vector<uint8_t> ciphertext;
    AuthTag tag;
    
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> result;
        result.insert(result.end(), nonce.data.begin(), nonce.data.end());
        result.insert(result.end(), ciphertext.begin(), ciphertext.end());
        result.insert(result.end(), tag.data.begin(), tag.data.end());
        return result;
    }
};

/**
 * @brief Message chiffré complet
 */
struct EncryptedMessage {
    MessageType type;
    AEADCiphertext encrypted_data;
    uint64_t sequence_number;
    uint64_t timestamp;
    
    std::vector<uint8_t> serialize() const {
        std::vector<uint8_t> result;
        result.push_back(static_cast<uint8_t>(type));
        
        // Sequence number (8 bytes)
        for (int i = 0; i < 8; ++i) {
            result.push_back((sequence_number >> (i * 8)) & 0xFF);
        }
        
        // Timestamp (8 bytes)
        for (int i = 0; i < 8; ++i) {
            result.push_back((timestamp >> (i * 8)) & 0xFF);
        }
        
        // Encrypted data
        auto enc = encrypted_data.serialize();
        result.insert(result.end(), enc.begin(), enc.end());
        
        return result;
    }
};

/**
 * @brief Informations de la suite cryptographique
 */
struct SuiteInfo {
    CryptoSuiteID id;
    std::string name;
    std::string key_exchange;
    std::string symmetric_cipher;
    bool has_pqc;
    bool has_forward_secrecy;
    double performance_score;  // 0.0 to 1.0
    double security_score;     // 0.0 to 1.0
    
    std::string description() const {
        return name + " (" + key_exchange + " + " + symmetric_cipher + 
               ", PQC: " + (has_pqc ? "Yes" : "No") + 
               ", FS: " + (has_forward_secrecy ? "Yes" : "No") + ")";
    }
};

} // namespace crypto
} // namespace mixnet

#endif // CRYPTO_TYPES_H
