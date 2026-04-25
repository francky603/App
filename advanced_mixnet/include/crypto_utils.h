/**
 * @file crypto_utils.h
 * @brief Utilitaires cryptographiques communs
 * 
 * Fonctions utilitaires pour:
 * - Génération de nombres aléatoires sécurisés
 * - Hash SHA256
 * - Encodage Hex/Base64
 * - Opérations temporelles
 */

#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include "crypto_types.h"
#include <random>
#include <chrono>
#include <sstream>
#include <iomanip>

namespace mixnet {
namespace utils {

// ============================================================================
// Générateur de nombres aléatoires sécurisé (CSPRNG)
// ============================================================================

/**
 * @brief Génère des bytes aléatoires cryptographiquement sûrs
 */
class SecureRandom {
public:
    /**
     * @brief Remplit un buffer avec des bytes aléatoires
     */
    static void generate_bytes(uint8_t* buffer, size_t length);
    
    /**
     * @brief Génère un tableau de bytes aléatoires
     */
    template<size_t N>
    static std::array<uint8_t, N> generate_array() {
        std::array<uint8_t, N> arr;
        generate_bytes(arr.data(), N);
        return arr;
    }
    
    /**
     * @brief Génère un vecteur de bytes aléatoires
     */
    static std::vector<uint8_t> generate_vector(size_t length);
    
    /**
     * @brief Génère un entier aléatoire dans [min, max]
     */
    static uint64_t random_range(uint64_t min, uint64_t max);
};

// ============================================================================
// Hash SHA256
// ============================================================================

/**
 * @brief Calcule le hash SHA256 d'une donnée
 */
class SHA256 {
public:
    /**
     * @brief Hash d'un buffer de bytes
     * @return 32 bytes de hash
     */
    static std::array<uint8_t, 32> hash(const uint8_t* data, size_t length);
    
    /**
     * @brief Hash d'un vecteur de bytes
     */
    static std::array<uint8_t, 32> hash(const std::vector<uint8_t>& data);
    
    /**
     * @brief Hash d'une chaîne de caractères
     */
    static std::array<uint8_t, 32> hash(const std::string& text);
    
    /**
     * @brief Hash hexadécimal (64 caractères)
     */
    static std::string hash_hex(const std::vector<uint8_t>& data);
    static std::string hash_hex(const std::string& text);
};

// ============================================================================
// Encodage/Décodage
// ============================================================================

/**
 * @brief Encodage hexadecimal
 */
class HexEncoder {
public:
    /**
     * @brief Encode des bytes en hex
     */
    static std::string encode(const uint8_t* data, size_t length);
    static std::string encode(const std::vector<uint8_t>& data);
    
    /**
     * @brief Décode une chaîne hex en bytes
     */
    static std::vector<uint8_t> decode(const std::string& hex);
};

/**
 * @brief Encodage Base64
 */
class Base64 {
public:
    /**
     * @brief Encode des bytes en Base64
     */
    static std::string encode(const uint8_t* data, size_t length);
    static std::string encode(const std::vector<uint8_t>& data);
    
    /**
     * @brief Décode une chaîne Base64 en bytes
     */
    static std::vector<uint8_t> decode(const std::string& base64);
};

// ============================================================================
// Utilitaires Temporels
// ============================================================================

/**
 * @brief Obtient le timestamp actuel en millisecondes (UTC)
 */
inline uint64_t get_timestamp_ms() {
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::milliseconds>(duration).count();
}

/**
 * @brief Obtient le timestamp actuel en secondes
 */
inline uint64_t get_timestamp_sec() {
    auto now = std::chrono::system_clock::now();
    auto duration = now.time_since_epoch();
    return std::chrono::duration_cast<std::chrono::seconds>(duration).count();
}

/**
 * @brief Formate un timestamp en chaîne lisible
 */
std::string format_timestamp(uint64_t timestamp_ms);

// ============================================================================
// Vérifications et Validations
// ============================================================================

/**
 * @brief Compare deux buffers en temps constant (timing-safe)
 */
bool constant_time_compare(const uint8_t* a, const uint8_t* b, size_t length);
bool constant_time_compare(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);

/**
 * @brief Vérifie qu'un tag d'authentification est valide
 */
bool verify_auth_tag(const crypto::AuthTag& expected, const crypto::AuthTag& received);

// ============================================================================
// Sérialisation
// ============================================================================

/**
 * @brief Serialize un entier 64-bit en bytes (little-endian)
 */
std::vector<uint8_t> serialize_uint64(uint64_t value);

/**
 * @brief Deserialize un entier 64-bit depuis des bytes (little-endian)
 */
uint64_t deserialize_uint64(const uint8_t* data, size_t offset = 0);

/**
 * @brief Concatène plusieurs buffers
 */
std::vector<uint8_t> concat_buffers(const std::vector<std::vector<uint8_t>>& buffers);
std::vector<uint8_t> concat_buffers(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b);

// ============================================================================
// Debug et Logging
// ============================================================================

/**
 * @brief Dump des bytes en format hex pour debug
 */
std::string dump_hex(const uint8_t* data, size_t length, size_t max_bytes = 64);
std::string dump_hex(const std::vector<uint8_t>& data, size_t max_bytes = 64);

/**
 * @brief Affiche les informations d'une suite cryptographique
 */
void print_suite_info(const crypto::SuiteInfo& info);

} // namespace utils
} // namespace mixnet

#endif // CRYPTO_UTILS_H
