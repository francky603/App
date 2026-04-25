/**
 * @file crypto_suite.cpp
 * @brief Implémentation des 9 suites cryptographiques et de la factory
 */

#include "crypto_suite.h"
#include "crypto_utils.h"
#include <random>
#include <cstring>
#include <iostream>

namespace mixnet {
namespace crypto {

// ============================================================================
// Helper: Simple XOR-based encryption for demonstration
// In production, use AES-NI, OpenSSL, or dedicated crypto libraries
// ============================================================================

namespace {
    // Simple PRNG for deterministic encryption (demo only!)
    class SimpleCipher {
    public:
        static void xor_cipher(uint8_t* data, size_t length, const uint8_t* key, size_t key_len) {
            for (size_t i = 0; i < length; ++i) {
                data[i] ^= key[i % key_len];
            }
        }
        
        static void generate_keystream(uint8_t* keystream, size_t length, 
                                       const SymmetricKey& key, const Nonce& nonce) {
            // Simple counter-mode-like keystream generation
            std::vector<uint8_t> counter_data = nonce.data;
            
            for (size_t i = 0; i < length; i += 32) {
                auto hash = utils::SHA256::hash(utils::concat_buffers(
                    std::vector<uint8_t>(key.data_ptr(), key.data_ptr() + key.size()),
                    counter_data
                ));
                
                size_t copy_len = std::min(size_t(32), length - i);
                std::memcpy(keystream + i, hash.data(), copy_len);
                
                // Increment counter
                for (int j = 0; j < 8 && j < counter_data.size(); ++j) {
                    if (++counter_data[j] != 0) break;
                }
            }
        }
    };
}

// ============================================================================
// Suite 1: RSA + AES-256-GCM
// ============================================================================

class RsaAesGcm : public ICryptoSuite {
public:
    CryptoSuiteID get_id() const override { return CryptoSuiteID::RSA_AES_GCM; }
    
    std::string get_name() const override { return "RSA-AES-GCM"; }
    
    SuiteInfo get_info() const override {
        return {
            CryptoSuiteID::RSA_AES_GCM,
            "RSA-AES-GCM",
            "RSA-2048",
            "AES-256-GCM",
            false,  // PQC
            false,  // Forward Secrecy
            0.6,    // Performance
            0.8     // Security
        };
    }
    
    KeyExchangeResult generate_keypair() override {
        KeyExchangeResult result;
        // Simulated RSA keypair (in production, use real RSA)
        result.public_key = utils::SecureRandom::generate_vector(RSA_2048_MODULUS_SIZE);
        result.success = true;
        return result;
    }
    
    std::array<uint8_t, SHARED_SECRET_SIZE> derive_shared_secret(
        const std::vector<uint8_t>& private_key,
        const std::vector<uint8_t>& peer_public_key
    ) override {
        // Derive shared secret using SHA256
        auto combined = utils::concat_buffers(private_key, peer_public_key);
        auto hash = utils::SHA256::hash(combined);
        
        std::array<uint8_t, SHARED_SECRET_SIZE> secret;
        std::memcpy(secret.data(), hash.data(), SHARED_SECRET_SIZE);
        return secret;
    }
    
    KeyExchangeResult kem_encapsulate(const std::vector<uint8_t>& peer_public_key) override {
        KeyExchangeResult result;
        result.ciphertext = utils::SecureRandom::generate_vector(RSA_2048_MODULUS_SIZE);
        result.shared_secret = utils::SecureRandom::generate_array<SHARED_SECRET_SIZE>();
        result.success = true;
        return result;
    }
    
    std::optional<std::array<uint8_t, SHARED_SECRET_SIZE>> kem_decapsulate(
        const std::vector<uint8_t>& private_key,
        const std::vector<uint8_t>& ciphertext
    ) override {
        // Simulated decapsulation
        auto hash = utils::SHA256::hash(utils::concat_buffers(private_key, ciphertext));
        std::array<uint8_t, SHARED_SECRET_SIZE> secret;
        std::memcpy(secret.data(), hash.data(), SHARED_SECRET_SIZE);
        return secret;
    }
    
    AEADCiphertext encrypt(const SymmetricKey& key,
                          const std::vector<uint8_t>& plaintext,
                          const std::vector<uint8_t>& aad) override {
        AEADCiphertext result;
        result.nonce = Nonce(AES_GCM_NONCE_SIZE);
        utils::SecureRandom::generate_bytes(result.nonce.data_ptr(), AES_GCM_NONCE_SIZE);
        
        result.ciphertext = plaintext;
        
        // Generate keystream and XOR
        std::vector<uint8_t> keystream(plaintext.size());
        SimpleCipher::generate_keystream(keystream.data(), plaintext.size(), key, result.nonce);
        SimpleCipher::xor_cipher(result.ciphertext.data(), plaintext.size(), 
                                keystream.data(), keystream.size());
        
        // Generate auth tag (simplified)
        auto tag_data = utils::concat_buffers({aad, result.ciphertext, result.nonce.data});
        auto tag_hash = utils::SHA256::hash(tag_data);
        std::memcpy(result.tag.data_ptr(), tag_hash.data(), AES_GCM_TAG_SIZE);
        
        return result;
    }
    
    std::optional<std::vector<uint8_t>> decrypt(const SymmetricKey& key,
                                                const Nonce& nonce,
                                                const std::vector<uint8_t>& ciphertext,
                                                const AuthTag& tag,
                                                const std::vector<uint8_t>& aad) override {
        // Verify tag first (simplified)
        auto tag_data = utils::concat_buffers({aad, ciphertext, nonce.data});
        auto expected_tag = utils::SHA256::hash(tag_data);
        
        AuthTag expected;
        std::memcpy(expected.data_ptr(), expected_tag.data(), AES_GCM_TAG_SIZE);
        
        if (!utils::verify_auth_tag(expected, tag)) {
            return std::nullopt;
        }
        
        // Decrypt
        std::vector<uint8_t> plaintext = ciphertext;
        std::vector<uint8_t> keystream(ciphertext.size());
        SimpleCipher::generate_keystream(keystream.data(), ciphertext.size(), key, nonce);
        SimpleCipher::xor_cipher(plaintext.data(), ciphertext.size(), 
                                keystream.data(), keystream.size());
        
        return plaintext;
    }
    
    SymmetricKey derive_symmetric_key(
        const std::array<uint8_t, SHARED_SECRET_SIZE>& shared_secret,
        const std::string& context
    ) override {
        auto input = utils::concat_buffers(
            std::vector<uint8_t>(shared_secret.begin(), shared_secret.end()),
            std::vector<uint8_t>(context.begin(), context.end())
        );
        auto hash = utils::SHA256::hash(input);
        
        SymmetricKey key;
        std::memcpy(key.data_ptr(), hash.data(), AES_256_KEY_SIZE);
        return key;
    }
    
    std::unique_ptr<ICryptoSuite> clone() const override {
        return std::make_unique<RsaAesGcm>();
    }
    
    void reset() override {}
};

// ============================================================================
// Suite 2: X25519 + AES-256-GCM
// ============================================================================

class X25519AesGcm : public ICryptoSuite {
public:
    CryptoSuiteID get_id() const override { return CryptoSuiteID::X25519_AES_GCM; }
    std::string get_name() const override { return "X25519-AES-GCM"; }
    
    SuiteInfo get_info() const override {
        return {
            CryptoSuiteID::X25519_AES_GCM,
            "X25519-AES-GCM",
            "X25519 ECDH",
            "AES-256-GCM",
            false, true, 0.9, 0.9
        };
    }
    
    KeyExchangeResult generate_keypair() override {
        KeyExchangeResult result;
        result.public_key = utils::SecureRandom::generate_vector(X25519_PUBLIC_SIZE);
        result.success = true;
        return result;
    }
    
    std::array<uint8_t, SHARED_SECRET_SIZE> derive_shared_secret(
        const std::vector<uint8_t>& private_key,
        const std::vector<uint8_t>& peer_public_key
    ) override {
        // Simulated X25519 ECDH
        auto combined = utils::concat_buffers(private_key, peer_public_key);
        auto hash = utils::SHA256::hash(combined);
        
        std::array<uint8_t, SHARED_SECRET_SIZE> secret;
        std::memcpy(secret.data(), hash.data(), SHARED_SECRET_SIZE);
        return secret;
    }
    
    KeyExchangeResult kem_encapsulate(const std::vector<uint8_t>&) override {
        return KeyExchangeResult{}; // Not applicable for pure ECDH
    }
    
    std::optional<std::array<uint8_t, SHARED_SECRET_SIZE>> kem_decapsulate(
        const std::vector<uint8_t>&, const std::vector<uint8_t>&) override {
        return std::nullopt; // Not applicable
    }
    
    AEADCiphertext encrypt(const SymmetricKey& key,
                          const std::vector<uint8_t>& plaintext,
                          const std::vector<uint8_t>& aad) override {
        // Same implementation as RsaAesGcm (AES-GCM)
        AEADCiphertext result;
        result.nonce = Nonce(AES_GCM_NONCE_SIZE);
        utils::SecureRandom::generate_bytes(result.nonce.data_ptr(), AES_GCM_NONCE_SIZE);
        
        result.ciphertext = plaintext;
        std::vector<uint8_t> keystream(plaintext.size());
        SimpleCipher::generate_keystream(keystream.data(), plaintext.size(), key, result.nonce);
        SimpleCipher::xor_cipher(result.ciphertext.data(), plaintext.size(), 
                                keystream.data(), keystream.size());
        
        auto tag_data = utils::concat_buffers({aad, result.ciphertext, result.nonce.data});
        auto tag_hash = utils::SHA256::hash(tag_data);
        std::memcpy(result.tag.data_ptr(), tag_hash.data(), AES_GCM_TAG_SIZE);
        
        return result;
    }
    
    std::optional<std::vector<uint8_t>> decrypt(const SymmetricKey& key,
                                                const Nonce& nonce,
                                                const std::vector<uint8_t>& ciphertext,
                                                const AuthTag& tag,
                                                const std::vector<uint8_t>& aad) override {
        auto tag_data = utils::concat_buffers({aad, ciphertext, nonce.data});
        auto expected_tag = utils::SHA256::hash(tag_data);
        
        AuthTag expected;
        std::memcpy(expected.data_ptr(), expected_tag.data(), AES_GCM_TAG_SIZE);
        
        if (!utils::verify_auth_tag(expected, tag)) {
            return std::nullopt;
        }
        
        std::vector<uint8_t> plaintext = ciphertext;
        std::vector<uint8_t> keystream(ciphertext.size());
        SimpleCipher::generate_keystream(keystream.data(), ciphertext.size(), key, nonce);
        SimpleCipher::xor_cipher(plaintext.data(), ciphertext.size(), 
                                keystream.data(), keystream.size());
        
        return plaintext;
    }
    
    SymmetricKey derive_symmetric_key(
        const std::array<uint8_t, SHARED_SECRET_SIZE>& shared_secret,
        const std::string& context
    ) override {
        auto input = utils::concat_buffers(
            std::vector<uint8_t>(shared_secret.begin(), shared_secret.end()),
            std::vector<uint8_t>(context.begin(), context.end())
        );
        auto hash = utils::SHA256::hash(input);
        
        SymmetricKey key;
        std::memcpy(key.data_ptr(), hash.data(), AES_256_KEY_SIZE);
        return key;
    }
    
    std::unique_ptr<ICryptoSuite> clone() const override {
        return std::make_unique<X25519AesGcm>();
    }
    
    void reset() override {}
};

// ============================================================================
// Suite 3: XChaCha20 + Poly1305
// ============================================================================

class XChaCha20Poly1305Suite : public ICryptoSuite {
public:
    CryptoSuiteID get_id() const override { return CryptoSuiteID::XCHACHA20_POLY1305; }
    std::string get_name() const override { return "XChaCha20-Poly1305"; }
    
    SuiteInfo get_info() const override {
        return {
            CryptoSuiteID::XCHACHA20_POLY1305,
            "XChaCha20-Poly1305",
            "X25519 ECDH",
            "XChaCha20-Poly1305",
            false, true, 1.0, 0.9
        };
    }
    
    KeyExchangeResult generate_keypair() override {
        KeyExchangeResult result;
        result.public_key = utils::SecureRandom::generate_vector(X25519_PUBLIC_SIZE);
        result.success = true;
        return result;
    }
    
    std::array<uint8_t, SHARED_SECRET_SIZE> derive_shared_secret(
        const std::vector<uint8_t>& private_key,
        const std::vector<uint8_t>& peer_public_key
    ) override {
        auto combined = utils::concat_buffers(private_key, peer_public_key);
        auto hash = utils::SHA256::hash(combined);
        
        std::array<uint8_t, SHARED_SECRET_SIZE> secret;
        std::memcpy(secret.data(), hash.data(), SHARED_SECRET_SIZE);
        return secret;
    }
    
    KeyExchangeResult kem_encapsulate(const std::vector<uint8_t>&) override {
        return KeyExchangeResult{};
    }
    
    std::optional<std::array<uint8_t, SHARED_SECRET_SIZE>> kem_decapsulate(
        const std::vector<uint8_t>&, const std::vector<uint8_t>&) override {
        return std::nullopt;
    }
    
    AEADCiphertext encrypt(const SymmetricKey& key,
                          const std::vector<uint8_t>& plaintext,
                          const std::vector<uint8_t>& aad) override {
        AEADCiphertext result;
        result.nonce = Nonce(XCHACHA20_NONCE_SIZE);  // Extended nonce!
        utils::SecureRandom::generate_bytes(result.nonce.data_ptr(), XCHACHA20_NONCE_SIZE);
        
        result.ciphertext = plaintext;
        std::vector<uint8_t> keystream(plaintext.size());
        SimpleCipher::generate_keystream(keystream.data(), plaintext.size(), key, result.nonce);
        SimpleCipher::xor_cipher(result.ciphertext.data(), plaintext.size(), 
                                keystream.data(), keystream.size());
        
        // Poly1305-like tag
        auto tag_data = utils::concat_buffers({aad, result.ciphertext, result.nonce.data});
        auto tag_hash = utils::SHA256::hash(tag_data);
        std::memcpy(result.tag.data_ptr(), tag_hash.data(), POLY1305_TAG_SIZE);
        
        return result;
    }
    
    std::optional<std::vector<uint8_t>> decrypt(const SymmetricKey& key,
                                                const Nonce& nonce,
                                                const std::vector<uint8_t>& ciphertext,
                                                const AuthTag& tag,
                                                const std::vector<uint8_t>& aad) override {
        auto tag_data = utils::concat_buffers({aad, ciphertext, nonce.data});
        auto expected_tag = utils::SHA256::hash(tag_data);
        
        AuthTag expected;
        std::memcpy(expected.data_ptr(), expected_tag.data(), POLY1305_TAG_SIZE);
        
        if (!utils::verify_auth_tag(expected, tag)) {
            return std::nullopt;
        }
        
        std::vector<uint8_t> plaintext = ciphertext;
        std::vector<uint8_t> keystream(ciphertext.size());
        SimpleCipher::generate_keystream(keystream.data(), ciphertext.size(), key, nonce);
        SimpleCipher::xor_cipher(plaintext.data(), ciphertext.size(), 
                                keystream.data(), keystream.size());
        
        return plaintext;
    }
    
    SymmetricKey derive_symmetric_key(
        const std::array<uint8_t, SHARED_SECRET_SIZE>& shared_secret,
        const std::string& context
    ) override {
        auto input = utils::concat_buffers(
            std::vector<uint8_t>(shared_secret.begin(), shared_secret.end()),
            std::vector<uint8_t>(context.begin(), context.end())
        );
        auto hash = utils::SHA256::hash(input);
        
        SymmetricKey key;
        std::memcpy(key.data_ptr(), hash.data(), AES_256_KEY_SIZE);
        return key;
    }
    
    std::unique_ptr<ICryptoSuite> clone() const override {
        return std::make_unique<XChaCha20Poly1305Suite>();
    }
    
    void reset() override {}
};

// ============================================================================
// Suite 4: AEGIS + X25519
// ============================================================================

class AegisAesGcm : public ICryptoSuite {
public:
    CryptoSuiteID get_id() const override { return CryptoSuiteID::AEGIS_X25519; }
    std::string get_name() const override { return "AEGIS-X25519"; }
    
    SuiteInfo get_info() const override {
        return {
            CryptoSuiteID::AEGIS_X25519,
            "AEGIS-X25519",
            "X25519 ECDH",
            "ChaCha20-Poly1305 (AEGIS)",
            false, true, 1.0, 0.9
        };
    }
    
    KeyExchangeResult generate_keypair() override {
        KeyExchangeResult result;
        result.public_key = utils::SecureRandom::generate_vector(X25519_PUBLIC_SIZE);
        result.success = true;
        return result;
    }
    
    std::array<uint8_t, SHARED_SECRET_SIZE> derive_shared_secret(
        const std::vector<uint8_t>& private_key,
        const std::vector<uint8_t>& peer_public_key
    ) override {
        auto combined = utils::concat_buffers(private_key, peer_public_key);
        auto hash = utils::SHA256::hash(combined);
        
        std::array<uint8_t, SHARED_SECRET_SIZE> secret;
        std::memcpy(secret.data(), hash.data(), SHARED_SECRET_SIZE);
        return secret;
    }
    
    KeyExchangeResult kem_encapsulate(const std::vector<uint8_t>&) override {
        return KeyExchangeResult{};
    }
    
    std::optional<std::array<uint8_t, SHARED_SECRET_SIZE>> kem_decapsulate(
        const std::vector<uint8_t>&, const std::vector<uint8_t>&) override {
        return std::nullopt;
    }
    
    AEADCiphertext encrypt(const SymmetricKey& key,
                          const std::vector<uint8_t>& plaintext,
                          const std::vector<uint8_t>& aad) override {
        AEADCiphertext result;
        result.nonce = Nonce(AES_GCM_NONCE_SIZE);
        utils::SecureRandom::generate_bytes(result.nonce.data_ptr(), AES_GCM_NONCE_SIZE);
        
        result.ciphertext = plaintext;
        std::vector<uint8_t> keystream(plaintext.size());
        SimpleCipher::generate_keystream(keystream.data(), plaintext.size(), key, result.nonce);
        SimpleCipher::xor_cipher(result.ciphertext.data(), plaintext.size(), 
                                keystream.data(), keystream.size());
        
        auto tag_data = utils::concat_buffers({aad, result.ciphertext, result.nonce.data});
        auto tag_hash = utils::SHA256::hash(tag_data);
        std::memcpy(result.tag.data_ptr(), tag_hash.data(), AES_GCM_TAG_SIZE);
        
        return result;
    }
    
    std::optional<std::vector<uint8_t>> decrypt(const SymmetricKey& key,
                                                const Nonce& nonce,
                                                const std::vector<uint8_t>& ciphertext,
                                                const AuthTag& tag,
                                                const std::vector<uint8_t>& aad) override {
        auto tag_data = utils::concat_buffers({aad, ciphertext, nonce.data});
        auto expected_tag = utils::SHA256::hash(tag_data);
        
        AuthTag expected;
        std::memcpy(expected.data_ptr(), expected_tag.data(), AES_GCM_TAG_SIZE);
        
        if (!utils::verify_auth_tag(expected, tag)) {
            return std::nullopt;
        }
        
        std::vector<uint8_t> plaintext = ciphertext;
        std::vector<uint8_t> keystream(ciphertext.size());
        SimpleCipher::generate_keystream(keystream.data(), ciphertext.size(), key, nonce);
        SimpleCipher::xor_cipher(plaintext.data(), ciphertext.size(), 
                                keystream.data(), keystream.size());
        
        return plaintext;
    }
    
    SymmetricKey derive_symmetric_key(
        const std::array<uint8_t, SHARED_SECRET_SIZE>& shared_secret,
        const std::string& context
    ) override {
        auto input = utils::concat_buffers(
            std::vector<uint8_t>(shared_secret.begin(), shared_secret.end()),
            std::vector<uint8_t>(context.begin(), context.end())
        );
        auto hash = utils::SHA256::hash(input);
        
        SymmetricKey key;
        std::memcpy(key.data_ptr(), hash.data(), AES_256_KEY_SIZE);
        return key;
    }
    
    std::unique_ptr<ICryptoSuite> clone() const override {
        return std::make_unique<AegisAesGcm>();
    }
    
    void reset() override {}
};

// ============================================================================
// Suite 5: Hybrid X25519+RSA
// ============================================================================

class HybridX25519Rsa : public ICryptoSuite {
public:
    CryptoSuiteID get_id() const override { return CryptoSuiteID::HYBRID_X25519_RSA; }
    std::string get_name() const override { return "Hybrid-X25519-RSA"; }
    
    SuiteInfo get_info() const override {
        return {
            CryptoSuiteID::HYBRID_X25519_RSA,
            "Hybrid-X25519-RSA",
            "X25519 + RSA-2048",
            "AES-256-GCM",
            false, true, 0.7, 1.0
        };
    }
    
    KeyExchangeResult generate_keypair() override {
        KeyExchangeResult result;
        // Hybrid: both X25519 and RSA keys
        auto x25519_key = utils::SecureRandom::generate_vector(X25519_PUBLIC_SIZE);
        auto rsa_key = utils::SecureRandom::generate_vector(RSA_2048_MODULUS_SIZE);
        
        result.public_key = x25519_key;
        result.public_key.insert(result.public_key.end(), rsa_key.begin(), rsa_key.end());
        result.success = true;
        return result;
    }
    
    std::array<uint8_t, SHARED_SECRET_SIZE> derive_shared_secret(
        const std::vector<uint8_t>& private_key,
        const std::vector<uint8_t>& peer_public_key
    ) override {
        // Combine both X25519 and RSA secrets
        auto hash = utils::SHA256::hash(utils::concat_buffers(private_key, peer_public_key));
        
        std::array<uint8_t, SHARED_SECRET_SIZE> secret;
        std::memcpy(secret.data(), hash.data(), SHARED_SECRET_SIZE);
        return secret;
    }
    
    KeyExchangeResult kem_encapsulate(const std::vector<uint8_t>& peer_public_key) override {
        KeyExchangeResult result;
        result.ciphertext = utils::SecureRandom::generate_vector(RSA_2048_MODULUS_SIZE);
        result.shared_secret = utils::SecureRandom::generate_array<SHARED_SECRET_SIZE>();
        result.success = true;
        return result;
    }
    
    std::optional<std::array<uint8_t, SHARED_SECRET_SIZE>> kem_decapsulate(
        const std::vector<uint8_t>& private_key,
        const std::vector<uint8_t>& ciphertext
    ) override {
        auto hash = utils::SHA256::hash(utils::concat_buffers(private_key, ciphertext));
        std::array<uint8_t, SHARED_SECRET_SIZE> secret;
        std::memcpy(secret.data(), hash.data(), SHARED_SECRET_SIZE);
        return secret;
    }
    
    AEADCiphertext encrypt(const SymmetricKey& key,
                          const std::vector<uint8_t>& plaintext,
                          const std::vector<uint8_t>& aad) override {
        AEADCiphertext result;
        result.nonce = Nonce(AES_GCM_NONCE_SIZE);
        utils::SecureRandom::generate_bytes(result.nonce.data_ptr(), AES_GCM_NONCE_SIZE);
        
        result.ciphertext = plaintext;
        std::vector<uint8_t> keystream(plaintext.size());
        SimpleCipher::generate_keystream(keystream.data(), plaintext.size(), key, result.nonce);
        SimpleCipher::xor_cipher(result.ciphertext.data(), plaintext.size(), 
                                keystream.data(), keystream.size());
        
        auto tag_data = utils::concat_buffers({aad, result.ciphertext, result.nonce.data});
        auto tag_hash = utils::SHA256::hash(tag_data);
        std::memcpy(result.tag.data_ptr(), tag_hash.data(), AES_GCM_TAG_SIZE);
        
        return result;
    }
    
    std::optional<std::vector<uint8_t>> decrypt(const SymmetricKey& key,
                                                const Nonce& nonce,
                                                const std::vector<uint8_t>& ciphertext,
                                                const AuthTag& tag,
                                                const std::vector<uint8_t>& aad) override {
        auto tag_data = utils::concat_buffers({aad, ciphertext, nonce.data});
        auto expected_tag = utils::SHA256::hash(tag_data);
        
        AuthTag expected;
        std::memcpy(expected.data_ptr(), expected_tag.data(), AES_GCM_TAG_SIZE);
        
        if (!utils::verify_auth_tag(expected, tag)) {
            return std::nullopt;
        }
        
        std::vector<uint8_t> plaintext = ciphertext;
        std::vector<uint8_t> keystream(ciphertext.size());
        SimpleCipher::generate_keystream(keystream.data(), ciphertext.size(), key, nonce);
        SimpleCipher::xor_cipher(plaintext.data(), ciphertext.size(), 
                                keystream.data(), keystream.size());
        
        return plaintext;
    }
    
    SymmetricKey derive_symmetric_key(
        const std::array<uint8_t, SHARED_SECRET_SIZE>& shared_secret,
        const std::string& context
    ) override {
        auto input = utils::concat_buffers(
            std::vector<uint8_t>(shared_secret.begin(), shared_secret.end()),
            std::vector<uint8_t>(context.begin(), context.end())
        );
        auto hash = utils::SHA256::hash(input);
        
        SymmetricKey key;
        std::memcpy(key.data_ptr(), hash.data(), AES_256_KEY_SIZE);
        return key;
    }
    
    std::unique_ptr<ICryptoSuite> clone() const override {
        return std::make_unique<HybridX25519Rsa>();
    }
    
    void reset() override {}
};

// ============================================================================
// Suite 6: ML-KEM + AES-256-GCM (Post-Quantum)
// ============================================================================

class MlKemAesGcm : public ICryptoSuite {
public:
    CryptoSuiteID get_id() const override { return CryptoSuiteID::ML_KEM_AES_GCM; }
    std::string get_name() const override { return "ML-KEM-AES-GCM"; }
    
    SuiteInfo get_info() const override {
        return {
            CryptoSuiteID::ML_KEM_AES_GCM,
            "ML-KEM-AES-GCM",
            "ML-KEM-768 (PQC)",
            "AES-256-GCM",
            true,   // PQC!
            true,   // Forward Secrecy
            0.7,    // Performance
            1.0     // Maximum security
        };
    }
    
    KeyExchangeResult generate_keypair() override {
        KeyExchangeResult result;
        // ML-KEM-768 key sizes
        result.public_key = utils::SecureRandom::generate_vector(1184);  // ML-KEM-768 public key
        result.success = true;
        return result;
    }
    
    std::array<uint8_t, SHARED_SECRET_SIZE> derive_shared_secret(
        const std::vector<uint8_t>& private_key,
        const std::vector<uint8_t>& peer_public_key
    ) override {
        auto hash = utils::SHA256::hash(utils::concat_buffers(private_key, peer_public_key));
        
        std::array<uint8_t, SHARED_SECRET_SIZE> secret;
        std::memcpy(secret.data(), hash.data(), SHARED_SECRET_SIZE);
        return secret;
    }
    
    KeyExchangeResult kem_encapsulate(const std::vector<uint8_t>& peer_public_key) override {
        KeyExchangeResult result;
        result.ciphertext = utils::SecureRandom::generate_vector(ML_KEM_CIPHERTEXT_SIZE);
        result.shared_secret = utils::SecureRandom::generate_array<SHARED_SECRET_SIZE>();
        result.success = true;
        return result;
    }
    
    std::optional<std::array<uint8_t, SHARED_SECRET_SIZE>> kem_decapsulate(
        const std::vector<uint8_t>& private_key,
        const std::vector<uint8_t>& ciphertext
    ) override {
        auto hash = utils::SHA256::hash(utils::concat_buffers(private_key, ciphertext));
        std::array<uint8_t, SHARED_SECRET_SIZE> secret;
        std::memcpy(secret.data(), hash.data(), SHARED_SECRET_SIZE);
        return secret;
    }
    
    AEADCiphertext encrypt(const SymmetricKey& key,
                          const std::vector<uint8_t>& plaintext,
                          const std::vector<uint8_t>& aad) override {
        AEADCiphertext result;
        result.nonce = Nonce(AES_GCM_NONCE_SIZE);
        utils::SecureRandom::generate_bytes(result.nonce.data_ptr(), AES_GCM_NONCE_SIZE);
        
        result.ciphertext = plaintext;
        std::vector<uint8_t> keystream(plaintext.size());
        SimpleCipher::generate_keystream(keystream.data(), plaintext.size(), key, result.nonce);
        SimpleCipher::xor_cipher(result.ciphertext.data(), plaintext.size(), 
                                keystream.data(), keystream.size());
        
        auto tag_data = utils::concat_buffers({aad, result.ciphertext, result.nonce.data});
        auto tag_hash = utils::SHA256::hash(tag_data);
        std::memcpy(result.tag.data_ptr(), tag_hash.data(), AES_GCM_TAG_SIZE);
        
        return result;
    }
    
    std::optional<std::vector<uint8_t>> decrypt(const SymmetricKey& key,
                                                const Nonce& nonce,
                                                const std::vector<uint8_t>& ciphertext,
                                                const AuthTag& tag,
                                                const std::vector<uint8_t>& aad) override {
        auto tag_data = utils::concat_buffers({aad, ciphertext, nonce.data});
        auto expected_tag = utils::SHA256::hash(tag_data);
        
        AuthTag expected;
        std::memcpy(expected.data_ptr(), expected_tag.data(), AES_GCM_TAG_SIZE);
        
        if (!utils::verify_auth_tag(expected, tag)) {
            return std::nullopt;
        }
        
        std::vector<uint8_t> plaintext = ciphertext;
        std::vector<uint8_t> keystream(ciphertext.size());
        SimpleCipher::generate_keystream(keystream.data(), ciphertext.size(), key, nonce);
        SimpleCipher::xor_cipher(plaintext.data(), ciphertext.size(), 
                                keystream.data(), keystream.size());
        
        return plaintext;
    }
    
    SymmetricKey derive_symmetric_key(
        const std::array<uint8_t, SHARED_SECRET_SIZE>& shared_secret,
        const std::string& context
    ) override {
        auto input = utils::concat_buffers(
            std::vector<uint8_t>(shared_secret.begin(), shared_secret.end()),
            std::vector<uint8_t>(context.begin(), context.end())
        );
        auto hash = utils::SHA256::hash(input);
        
        SymmetricKey key;
        std::memcpy(key.data_ptr(), hash.data(), AES_256_KEY_SIZE);
        return key;
    }
    
    std::unique_ptr<ICryptoSuite> clone() const override {
        return std::make_unique<MlKemAesGcm>();
    }
    
    void reset() override {}
};

// ============================================================================
// Suite 7: FrodoKEM + X25519 (Lattice-based PQC)
// ============================================================================

class FrodoKemX25519Suite : public ICryptoSuite {
public:
    CryptoSuiteID get_id() const override { return CryptoSuiteID::FRODO_KEM_X25519; }
    std::string get_name() const override { return "FrodoKEM-X25519"; }
    
    SuiteInfo get_info() const override {
        return {
            CryptoSuiteID::FRODO_KEM_X25519,
            "FrodoKEM-X25519",
            "FrodoKEM-640 (Lattice)",
            "AES-256-GCM",
            true, true, 0.6, 1.0
        };
    }
    
    KeyExchangeResult generate_keypair() override {
        KeyExchangeResult result;
        result.public_key = utils::SecureRandom::generate_vector(1152);  // FrodoKEM-640
        result.success = true;
        return result;
    }
    
    std::array<uint8_t, SHARED_SECRET_SIZE> derive_shared_secret(
        const std::vector<uint8_t>& private_key,
        const std::vector<uint8_t>& peer_public_key
    ) override {
        auto hash = utils::SHA256::hash(utils::concat_buffers(private_key, peer_public_key));
        
        std::array<uint8_t, SHARED_SECRET_SIZE> secret;
        std::memcpy(secret.data(), hash.data(), SHARED_SECRET_SIZE);
        return secret;
    }
    
    KeyExchangeResult kem_encapsulate(const std::vector<uint8_t>& peer_public_key) override {
        KeyExchangeResult result;
        result.ciphertext = utils::SecureRandom::generate_vector(FRODO_KEM_CIPHERTEXT_SIZE);
        result.shared_secret = utils::SecureRandom::generate_array<SHARED_SECRET_SIZE>();
        result.success = true;
        return result;
    }
    
    std::optional<std::array<uint8_t, SHARED_SECRET_SIZE>> kem_decapsulate(
        const std::vector<uint8_t>& private_key,
        const std::vector<uint8_t>& ciphertext
    ) override {
        auto hash = utils::SHA256::hash(utils::concat_buffers(private_key, ciphertext));
        std::array<uint8_t, SHARED_SECRET_SIZE> secret;
        std::memcpy(secret.data(), hash.data(), SHARED_SECRET_SIZE);
        return secret;
    }
    
    AEADCiphertext encrypt(const SymmetricKey& key,
                          const std::vector<uint8_t>& plaintext,
                          const std::vector<uint8_t>& aad) override {
        AEADCiphertext result;
        result.nonce = Nonce(AES_GCM_NONCE_SIZE);
        utils::SecureRandom::generate_bytes(result.nonce.data_ptr(), AES_GCM_NONCE_SIZE);
        
        result.ciphertext = plaintext;
        std::vector<uint8_t> keystream(plaintext.size());
        SimpleCipher::generate_keystream(keystream.data(), plaintext.size(), key, result.nonce);
        SimpleCipher::xor_cipher(result.ciphertext.data(), plaintext.size(), 
                                keystream.data(), keystream.size());
        
        auto tag_data = utils::concat_buffers({aad, result.ciphertext, result.nonce.data});
        auto tag_hash = utils::SHA256::hash(tag_data);
        std::memcpy(result.tag.data_ptr(), tag_hash.data(), AES_GCM_TAG_SIZE);
        
        return result;
    }
    
    std::optional<std::vector<uint8_t>> decrypt(const SymmetricKey& key,
                                                const Nonce& nonce,
                                                const std::vector<uint8_t>& ciphertext,
                                                const AuthTag& tag,
                                                const std::vector<uint8_t>& aad) override {
        auto tag_data = utils::concat_buffers({aad, ciphertext, nonce.data});
        auto expected_tag = utils::SHA256::hash(tag_data);
        
        AuthTag expected;
        std::memcpy(expected.data_ptr(), expected_tag.data(), AES_GCM_TAG_SIZE);
        
        if (!utils::verify_auth_tag(expected, tag)) {
            return std::nullopt;
        }
        
        std::vector<uint8_t> plaintext = ciphertext;
        std::vector<uint8_t> keystream(ciphertext.size());
        SimpleCipher::generate_keystream(keystream.data(), ciphertext.size(), key, nonce);
        SimpleCipher::xor_cipher(plaintext.data(), ciphertext.size(), 
                                keystream.data(), keystream.size());
        
        return plaintext;
    }
    
    SymmetricKey derive_symmetric_key(
        const std::array<uint8_t, SHARED_SECRET_SIZE>& shared_secret,
        const std::string& context
    ) override {
        auto input = utils::concat_buffers(
            std::vector<uint8_t>(shared_secret.begin(), shared_secret.end()),
            std::vector<uint8_t>(context.begin(), context.end())
        );
        auto hash = utils::SHA256::hash(input);
        
        SymmetricKey key;
        std::memcpy(key.data_ptr(), hash.data(), AES_256_KEY_SIZE);
        return key;
    }
    
    std::unique_ptr<ICryptoSuite> clone() const override {
        return std::make_unique<FrodoKemX25519Suite>();
    }
    
    void reset() override {}
};

// ============================================================================
// Suite 8: AES-GCM-SIV + FrodoKEM (Nonce-misuse resistant + PQC)
// ============================================================================

class AesGcmSivSuite : public ICryptoSuite {
public:
    CryptoSuiteID get_id() const override { return CryptoSuiteID::AES_GCM_SIV_FRODO; }
    std::string get_name() const override { return "AES-GCM-SIV-FrodoKEM"; }
    
    SuiteInfo get_info() const override {
        return {
            CryptoSuiteID::AES_GCM_SIV_FRODO,
            "AES-GCM-SIV-FrodoKEM",
            "FrodoKEM-640",
            "AES-GCM-SIV",
            true, true, 0.6, 1.0
        };
    }
    
    KeyExchangeResult generate_keypair() override {
        KeyExchangeResult result;
        result.public_key = utils::SecureRandom::generate_vector(1152);
        result.success = true;
        return result;
    }
    
    std::array<uint8_t, SHARED_SECRET_SIZE> derive_shared_secret(
        const std::vector<uint8_t>& private_key,
        const std::vector<uint8_t>& peer_public_key
    ) override {
        auto hash = utils::SHA256::hash(utils::concat_buffers(private_key, peer_public_key));
        
        std::array<uint8_t, SHARED_SECRET_SIZE> secret;
        std::memcpy(secret.data(), hash.data(), SHARED_SECRET_SIZE);
        return secret;
    }
    
    KeyExchangeResult kem_encapsulate(const std::vector<uint8_t>& peer_public_key) override {
        KeyExchangeResult result;
        result.ciphertext = utils::SecureRandom::generate_vector(FRODO_KEM_CIPHERTEXT_SIZE);
        result.shared_secret = utils::SecureRandom::generate_array<SHARED_SECRET_SIZE>();
        result.success = true;
        return result;
    }
    
    std::optional<std::array<uint8_t, SHARED_SECRET_SIZE>> kem_decapsulate(
        const std::vector<uint8_t>& private_key,
        const std::vector<uint8_t>& ciphertext
    ) override {
        auto hash = utils::SHA256::hash(utils::concat_buffers(private_key, ciphertext));
        std::array<uint8_t, SHARED_SECRET_SIZE> secret;
        std::memcpy(secret.data(), hash.data(), SHARED_SECRET_SIZE);
        return secret;
    }
    
    AEADCiphertext encrypt(const SymmetricKey& key,
                          const std::vector<uint8_t>& plaintext,
                          const std::vector<uint8_t>& aad) override {
        AEADCiphertext result;
        result.nonce = Nonce(AES_GCM_NONCE_SIZE);
        utils::SecureRandom::generate_bytes(result.nonce.data_ptr(), AES_GCM_NONCE_SIZE);
        
        result.ciphertext = plaintext;
        std::vector<uint8_t> keystream(plaintext.size());
        SimpleCipher::generate_keystream(keystream.data(), plaintext.size(), key, result.nonce);
        SimpleCipher::xor_cipher(result.ciphertext.data(), plaintext.size(), 
                                keystream.data(), keystream.size());
        
        auto tag_data = utils::concat_buffers({aad, result.ciphertext, result.nonce.data});
        auto tag_hash = utils::SHA256::hash(tag_data);
        std::memcpy(result.tag.data_ptr(), tag_hash.data(), AES_GCM_TAG_SIZE);
        
        return result;
    }
    
    std::optional<std::vector<uint8_t>> decrypt(const SymmetricKey& key,
                                                const Nonce& nonce,
                                                const std::vector<uint8_t>& ciphertext,
                                                const AuthTag& tag,
                                                const std::vector<uint8_t>& aad) override {
        auto tag_data = utils::concat_buffers({aad, ciphertext, nonce.data});
        auto expected_tag = utils::SHA256::hash(tag_data);
        
        AuthTag expected;
        std::memcpy(expected.data_ptr(), expected_tag.data(), AES_GCM_TAG_SIZE);
        
        if (!utils::verify_auth_tag(expected, tag)) {
            return std::nullopt;
        }
        
        std::vector<uint8_t> plaintext = ciphertext;
        std::vector<uint8_t> keystream(ciphertext.size());
        SimpleCipher::generate_keystream(keystream.data(), ciphertext.size(), key, nonce);
        SimpleCipher::xor_cipher(plaintext.data(), ciphertext.size(), 
                                keystream.data(), keystream.size());
        
        return plaintext;
    }
    
    SymmetricKey derive_symmetric_key(
        const std::array<uint8_t, SHARED_SECRET_SIZE>& shared_secret,
        const std::string& context
    ) override {
        auto input = utils::concat_buffers(
            std::vector<uint8_t>(shared_secret.begin(), shared_secret.end()),
            std::vector<uint8_t>(context.begin(), context.end())
        );
        auto hash = utils::SHA256::hash(input);
        
        SymmetricKey key;
        std::memcpy(key.data_ptr(), hash.data(), AES_256_KEY_SIZE);
        return key;
    }
    
    std::unique_ptr<ICryptoSuite> clone() const override {
        return std::make_unique<AesGcmSivSuite>();
    }
    
    void reset() override {}
};

// ============================================================================
// Suite 9: ML-DSA + X25519 (Post-Quantum Signatures)
// ============================================================================

class MlDsaX25519Suite : public ICryptoSuite {
public:
    CryptoSuiteID get_id() const override { return CryptoSuiteID::ML_DSA_X25519; }
    std::string get_name() const override { return "ML-DSA-X25519"; }
    
    SuiteInfo get_info() const override {
        return {
            CryptoSuiteID::ML_DSA_X25519,
            "ML-DSA-X25519",
            "X25519 + ML-DSA",
            "AES-256-GCM",
            true, true, 0.7, 1.0
        };
    }
    
    KeyExchangeResult generate_keypair() override {
        KeyExchangeResult result;
        // X25519 public key + ML-DSA public key
        auto x25519_pk = utils::SecureRandom::generate_vector(X25519_PUBLIC_SIZE);
        auto ml_dsa_pk = utils::SecureRandom::generate_vector(2592);  // ML-DSA-65
        
        result.public_key = x25519_pk;
        result.public_key.insert(result.public_key.end(), ml_dsa_pk.begin(), ml_dsa_pk.end());
        result.success = true;
        return result;
    }
    
    std::array<uint8_t, SHARED_SECRET_SIZE> derive_shared_secret(
        const std::vector<uint8_t>& private_key,
        const std::vector<uint8_t>& peer_public_key
    ) override {
        auto hash = utils::SHA256::hash(utils::concat_buffers(private_key, peer_public_key));
        
        std::array<uint8_t, SHARED_SECRET_SIZE> secret;
        std::memcpy(secret.data(), hash.data(), SHARED_SECRET_SIZE);
        return secret;
    }
    
    KeyExchangeResult kem_encapsulate(const std::vector<uint8_t>& peer_public_key) override {
        KeyExchangeResult result;
        result.ciphertext = utils::SecureRandom::generate_vector(X25519_PUBLIC_SIZE);
        result.shared_secret = utils::SecureRandom::generate_array<SHARED_SECRET_SIZE>();
        result.success = true;
        return result;
    }
    
    std::optional<std::array<uint8_t, SHARED_SECRET_SIZE>> kem_decapsulate(
        const std::vector<uint8_t>& private_key,
        const std::vector<uint8_t>& ciphertext
    ) override {
        auto hash = utils::SHA256::hash(utils::concat_buffers(private_key, ciphertext));
        std::array<uint8_t, SHARED_SECRET_SIZE> secret;
        std::memcpy(secret.data(), hash.data(), SHARED_SECRET_SIZE);
        return secret;
    }
    
    std::vector<uint8_t> sign(const std::vector<uint8_t>& private_key,
                             const std::vector<uint8_t>& message) override {
        // Simulated ML-DSA signature
        auto hash = utils::SHA256::hash(utils::concat_buffers(private_key, message));
        return std::vector<uint8_t>(hash.begin(), hash.end());
    }
    
    bool verify(const std::vector<uint8_t>& public_key,
               const std::vector<uint8_t>& message,
               const std::vector<uint8_t>& signature) override {
        // Simulated verification
        auto hash = utils::SHA256::hash(utils::concat_buffers(public_key, message));
        return std::equal(hash.begin(), hash.begin() + signature.size(), signature.begin());
    }
    
    AEADCiphertext encrypt(const SymmetricKey& key,
                          const std::vector<uint8_t>& plaintext,
                          const std::vector<uint8_t>& aad) override {
        AEADCiphertext result;
        result.nonce = Nonce(AES_GCM_NONCE_SIZE);
        utils::SecureRandom::generate_bytes(result.nonce.data_ptr(), AES_GCM_NONCE_SIZE);
        
        result.ciphertext = plaintext;
        std::vector<uint8_t> keystream(plaintext.size());
        SimpleCipher::generate_keystream(keystream.data(), plaintext.size(), key, result.nonce);
        SimpleCipher::xor_cipher(result.ciphertext.data(), plaintext.size(), 
                                keystream.data(), keystream.size());
        
        auto tag_data = utils::concat_buffers({aad, result.ciphertext, result.nonce.data});
        auto tag_hash = utils::SHA256::hash(tag_data);
        std::memcpy(result.tag.data_ptr(), tag_hash.data(), AES_GCM_TAG_SIZE);
        
        return result;
    }
    
    std::optional<std::vector<uint8_t>> decrypt(const SymmetricKey& key,
                                                const Nonce& nonce,
                                                const std::vector<uint8_t>& ciphertext,
                                                const AuthTag& tag,
                                                const std::vector<uint8_t>& aad) override {
        auto tag_data = utils::concat_buffers({aad, ciphertext, nonce.data});
        auto expected_tag = utils::SHA256::hash(tag_data);
        
        AuthTag expected;
        std::memcpy(expected.data_ptr(), expected_tag.data(), AES_GCM_TAG_SIZE);
        
        if (!utils::verify_auth_tag(expected, tag)) {
            return std::nullopt;
        }
        
        std::vector<uint8_t> plaintext = ciphertext;
        std::vector<uint8_t> keystream(ciphertext.size());
        SimpleCipher::generate_keystream(keystream.data(), ciphertext.size(), key, nonce);
        SimpleCipher::xor_cipher(plaintext.data(), ciphertext.size(), 
                                keystream.data(), keystream.size());
        
        return plaintext;
    }
    
    SymmetricKey derive_symmetric_key(
        const std::array<uint8_t, SHARED_SECRET_SIZE>& shared_secret,
        const std::string& context
    ) override {
        auto input = utils::concat_buffers(
            std::vector<uint8_t>(shared_secret.begin(), shared_secret.end()),
            std::vector<uint8_t>(context.begin(), context.end())
        );
        auto hash = utils::SHA256::hash(input);
        
        SymmetricKey key;
        std::memcpy(key.data_ptr(), hash.data(), AES_256_KEY_SIZE);
        return key;
    }
    
    std::unique_ptr<ICryptoSuite> clone() const override {
        return std::make_unique<MlDsaX25519Suite>();
    }
    
    void reset() override {}
};

// ============================================================================
// CryptoSuiteFactory Implementation
// ============================================================================

std::unique_ptr<ICryptoSuite> CryptoSuiteFactory::create_suite(CryptoSuiteID id) {
    switch (id) {
        case CryptoSuiteID::RSA_AES_GCM:
            return std::make_unique<RsaAesGcm>();
        case CryptoSuiteID::X25519_AES_GCM:
            return std::make_unique<X25519AesGcm>();
        case CryptoSuiteID::XCHACHA20_POLY1305:
            return std::make_unique<XChaCha20Poly1305Suite>();
        case CryptoSuiteID::AEGIS_X25519:
            return std::make_unique<AegisAesGcm>();
        case CryptoSuiteID::HYBRID_X25519_RSA:
            return std::make_unique<HybridX25519Rsa>();
        case CryptoSuiteID::ML_KEM_AES_GCM:
            return std::make_unique<MlKemAesGcm>();
        case CryptoSuiteID::FRODO_KEM_X25519:
            return std::make_unique<FrodoKemX25519Suite>();
        case CryptoSuiteID::AES_GCM_SIV_FRODO:
            return std::make_unique<AesGcmSivSuite>();
        case CryptoSuiteID::ML_DSA_X25519:
            return std::make_unique<MlDsaX25519Suite>();
        default:
            return nullptr;
    }
}

std::unique_ptr<ICryptoSuite> CryptoSuiteFactory::create_random_suite() {
    auto index = utils::SecureRandom::random_range(0, 8);
    auto id = static_cast<CryptoSuiteID>(index);
    return create_suite(id);
}

std::vector<SuiteInfo> CryptoSuiteFactory::get_all_suites() {
    std::vector<SuiteInfo> suites;
    
    for (int i = 0; i <= 8; ++i) {
        auto suite = create_suite(static_cast<CryptoSuiteID>(i));
        if (suite) {
            suites.push_back(suite->get_info());
        }
    }
    
    return suites;
}

SuiteInfo CryptoSuiteFactory::get_suite_info(CryptoSuiteID id) {
    auto suite = create_suite(id);
    if (suite) {
        return suite->get_info();
    }
    return SuiteInfo{};
}

} // namespace crypto
} // namespace mixnet
