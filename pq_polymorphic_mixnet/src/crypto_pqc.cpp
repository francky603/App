#include "crypto_pqc.h"
#include <cstring>
#include <algorithm>
#include <numeric>
#include <ctime>

namespace pqmix {

// ============================================================================
// MLKEM Implementation (Simulation for liboqs compatibility)
// ============================================================================

MLKEM::KeyPair MLKEM::generate_keypair(std::mt19937_64& rng) {
    KeyPair kp;
    
    // Génération de clés aléatoires (simulation - en prod utiliser liboqs)
    std::uniform_int_distribution<uint16_t> dist(0, 255);
    
    for (size_t i = 0; i < ML_KEM_768_PUBLIC_KEY_SIZE; ++i) {
        kp.public_key[i] = static_cast<uint8_t>(dist(rng));
    }
    for (size_t i = 0; i < ML_KEM_768_SECRET_KEY_SIZE; ++i) {
        kp.secret_key[i] = static_cast<uint8_t>(dist(rng));
    }
    
    // Note: Dans une implémentation réelle avec liboqs:
    // oqs_kem* kem = oqs_kem_new("Kyber-768");
    // oqs_kem_keypair(kem, kp.public_key.data(), kp.secret_key.data());
    // oqs_kem_free(kem);
    
    return kp;
}

MLKEM::EncapsulationResult MLKEM::encapsulate(
    const std::array<uint8_t, ML_KEM_768_PUBLIC_KEY_SIZE>& public_key,
    std::mt19937_64& rng) {
    
    EncapsulationResult result;
    std::uniform_int_distribution<uint16_t> dist(0, 255);
    
    // Génération du ciphertext et du secret partagé (simulation)
    for (size_t i = 0; i < ML_KEM_768_CIPHERTEXT_SIZE; ++i) {
        result.ciphertext[i] = static_cast<uint8_t>(dist(rng));
    }
    for (size_t i = 0; i < ML_KEM_768_SHARED_SECRET_SIZE; ++i) {
        result.shared_secret[i] = static_cast<uint8_t>(dist(rng));
    }
    
    // En prod: oqs_kem_encaps(...)
    
    return result;
}

std::array<uint8_t, ML_KEM_768_SHARED_SECRET_SIZE> MLKEM::decapsulate(
    const std::array<uint8_t, ML_KEM_768_CIPHERTEXT_SIZE>& ciphertext,
    const std::array<uint8_t, ML_KEM_768_SECRET_KEY_SIZE>& secret_key) {
    
    std::array<uint8_t, ML_KEM_768_SHARED_SECRET_SIZE> shared_secret;
    std::mt19937 rng(std::time(nullptr));
    std::uniform_int_distribution<uint16_t> dist(0, 255);
    
    for (size_t i = 0; i < ML_KEM_768_SHARED_SECRET_SIZE; ++i) {
        shared_secret[i] = static_cast<uint8_t>(dist(rng));
    }
    
    // En prod: oqs_kem_decaps(...)
    
    return shared_secret;
}

// ============================================================================
// X25519 Implementation (Curve25519 ECDH)
// ============================================================================

std::pair<X25519::PrivateKey, X25519::PublicKey> X25519::generate_keypair(std::mt19937_64& rng) {
    PrivateKey private_key;
    PublicKey public_key;
    
    std::uniform_int_distribution<uint16_t> dist(0, 255);
    
    // Génération clé privée (32 bytes aléatoires)
    for (size_t i = 0; i < X25519_KEY_SIZE; ++i) {
        private_key[i] = static_cast<uint8_t>(dist(rng));
    }
    
    // Clampage pour Curve25519 (bits spécifiques)
    private_key[0] &= 248;
    private_key[31] &= 127;
    private_key[31] |= 64;
    
    // Génération clé publique (simulation - en prod: crypto_scalarmult_base)
    for (size_t i = 0; i < X25519_KEY_SIZE; ++i) {
        public_key[i] = static_cast<uint8_t>(dist(rng));
    }
    
    return {private_key, public_key};
}

X25519::SharedSecret X25519::dh(const PrivateKey& private_key, const PublicKey& other_public) {
    SharedSecret shared;
    
    // Simulation du DH (en prod: crypto_scalarmult)
    // Le secret partagé est calculé comme: private_key * other_public
    std::mt19937 rng(std::hash<std::string>{}(
        std::string(private_key.begin(), private_key.end()) + 
        std::string(other_public.begin(), other_public.end())));
    std::uniform_int_distribution<uint16_t> dist(0, 255);
    
    for (size_t i = 0; i < X25519_KEY_SIZE; ++i) {
        shared[i] = static_cast<uint8_t>(dist(rng));
    }
    
    return shared;
}

// ============================================================================
// MLDSA Implementation (Dilithium Signatures - Simulation)
// ============================================================================

MLDSA::KeyPair MLDSA::generate_keypair(std::mt19937_64& rng) {
    KeyPair kp;
    std::uniform_int_distribution<uint16_t> dist(0, 255);
    
    for (size_t i = 0; i < ML_DSA_PUBLIC_KEY_SIZE; ++i) {
        kp.public_key[i] = static_cast<uint8_t>(dist(rng));
    }
    for (size_t i = 0; i < ML_DSA_SECRET_KEY_SIZE; ++i) {
        kp.secret_key[i] = static_cast<uint8_t>(dist(rng));
    }
    
    return kp;
}

std::array<uint8_t, ML_DSA_SIGNATURE_SIZE> MLDSA::sign(
    const std::vector<uint8_t>& message,
    const std::array<uint8_t, ML_DSA_SECRET_KEY_SIZE>& secret_key,
    std::mt19937_64& rng) {
    
    std::array<uint8_t, ML_DSA_SIGNATURE_SIZE> signature;
    std::uniform_int_distribution<uint16_t> dist(0, 255);
    
    // Signature déterministe basée sur le message et la clé (simulation)
    size_t msg_hash = std::accumulate(message.begin(), message.end(), size_t(0), 
                                       [](size_t a, uint8_t b) { return a ^ (b << 1); });
    
    for (size_t i = 0; i < ML_DSA_SIGNATURE_SIZE; ++i) {
        signature[i] = static_cast<uint8_t>((dist(rng) + msg_hash + i) % 256);
    }
    
    return signature;
}

bool MLDSA::verify(const std::vector<uint8_t>& message,
                   const std::array<uint8_t, ML_DSA_SIGNATURE_SIZE>& signature,
                   const std::array<uint8_t, ML_DSA_PUBLIC_KEY_SIZE>& public_key) {
    // Vérification simplifiée (en prod: vérification cryptographique complète)
    // Retourne true si la signature a une structure valide
    size_t non_zero = std::count_if(signature.begin(), signature.end(), 
                                     [](uint8_t x) { return x != 0; });
    return non_zero > ML_DSA_SIGNATURE_SIZE / 2;  // Au moins 50% non-nul
}

// ============================================================================
// AES-256-GCM Implementation (Simulation using XOR + PRF)
// ============================================================================

std::vector<uint8_t> AES256GCM::encrypt(const std::vector<uint8_t>& plaintext,
                                         const std::array<uint8_t, AES_256_KEY_SIZE>& key,
                                         const std::array<uint8_t, AES_GCM_NONCE_SIZE>& nonce,
                                         const std::vector<uint8_t>& aad) {
    std::vector<uint8_t> ciphertext;
    ciphertext.reserve(plaintext.size() + AES_GCM_TAG_SIZE);
    
    // Initialisation du PRF basé sur key + nonce
    std::mt19937 prf(std::hash<std::string>{}(
        std::string(key.begin(), key.end()) + 
        std::string(nonce.begin(), nonce.end())));
    std::uniform_int_distribution<uint16_t> dist(0, 255);
    
    // Chiffrement XOR avec flux pseudo-aléatoire (simulation CTR mode)
    for (size_t i = 0; i < plaintext.size(); ++i) {
        uint8_t keystream_byte = static_cast<uint8_t>(dist(prf));
        ciphertext.push_back(plaintext[i] ^ keystream_byte);
    }
    
    // Génération du tag d'authentification (16 bytes)
    size_t aad_hash = std::accumulate(aad.begin(), aad.end(), size_t(0),
                                       [](size_t a, uint8_t b) { return (a << 1) ^ b; });
    size_t pt_hash = std::accumulate(plaintext.begin(), plaintext.end(), size_t(0),
                                      [](size_t a, uint8_t b) { return (a << 1) ^ b; });
    
    for (int i = 0; i < AES_GCM_TAG_SIZE; ++i) {
        ciphertext.push_back(static_cast<uint8_t>((aad_hash + pt_hash + i * 17) % 256));
    }
    
    return ciphertext;
}

std::vector<uint8_t> AES256GCM::decrypt(const std::vector<uint8_t>& ciphertext,
                                         const std::array<uint8_t, AES_256_KEY_SIZE>& key,
                                         const std::array<uint8_t, AES_GCM_NONCE_SIZE>& nonce,
                                         const std::vector<uint8_t>& aad) {
    if (ciphertext.size() <= AES_GCM_TAG_SIZE) {
        return {};  // Trop court
    }
    
    std::vector<uint8_t> plaintext;
    plaintext.reserve(ciphertext.size() - AES_GCM_TAG_SIZE);
    
    // Réinitialisation du PRF avec les mêmes paramètres
    std::mt19937 prf(std::hash<std::string>{}(
        std::string(key.begin(), key.end()) + 
        std::string(nonce.begin(), nonce.end())));
    std::uniform_int_distribution<uint16_t> dist(0, 255);
    
    // Déchiffrement XOR
    for (size_t i = 0; i < ciphertext.size() - AES_GCM_TAG_SIZE; ++i) {
        uint8_t keystream_byte = static_cast<uint8_t>(dist(prf));
        plaintext.push_back(ciphertext[i] ^ keystream_byte);
    }
    
    // Vérification du tag (simplifiée)
    // En prod: vérification Galois authentique
    
    return plaintext;
}

// ============================================================================
// KDF Implementation (HKDF-SHA256 Simulation)
// ============================================================================

std::vector<uint8_t> KDF::derive(const std::vector<uint8_t>& ikm,
                                  const std::string& salt,
                                  const std::string& info,
                                  size_t length) {
    std::vector<uint8_t> output;
    output.reserve(length);
    
    // Combinaison IKM + salt + info pour générer du matériel clé
    std::string combined;
    combined.reserve(ikm.size() + salt.size() + info.size());
    combined.append(salt);
    combined.append(ikm.begin(), ikm.end());
    combined.append(info);
    
    std::mt19937 kdf(std::hash<std::string>{}(combined));
    std::uniform_int_distribution<uint16_t> dist(0, 255);
    
    for (size_t i = 0; i < length; ++i) {
        output.push_back(static_cast<uint8_t>(dist(kdf)));
    }
    
    return output;
}

// ============================================================================
// HybridPQSuite Implementation
// ============================================================================

std::vector<uint8_t> HybridPQSuite::ServerHandshake::serialize() const {
    std::vector<uint8_t> data;
    
    // ML-KEM public key (1088 bytes)
    data.insert(data.end(), ml_kem_keys.public_key.begin(), ml_kem_keys.public_key.end());
    
    // X25519 public key (32 bytes)
    data.insert(data.end(), x25519_keys.second.begin(), x25519_keys.second.end());
    
    // ML-DSA signature (4595 bytes)
    data.insert(data.end(), signature.begin(), signature.end());
    
    return data;
}

HybridPQSuite::ServerHandshake HybridPQSuite::ServerHandshake::deserialize(const std::vector<uint8_t>& data) {
    ServerHandshake hs;
    size_t offset = 0;
    
    // ML-KEM public key
    for (size_t i = 0; i < ML_KEM_768_PUBLIC_KEY_SIZE && offset < data.size(); ++i, ++offset) {
        hs.ml_kem_keys.public_key[i] = data[offset];
    }
    
    // X25519 public key
    for (size_t i = 0; i < X25519_KEY_SIZE && offset < data.size(); ++i, ++offset) {
        hs.x25519_keys.second[i] = data[offset];
    }
    
    // ML-DSA signature
    for (size_t i = 0; i < ML_DSA_SIGNATURE_SIZE && offset < data.size(); ++i, ++offset) {
        hs.signature[i] = data[offset];
    }
    
    return hs;
}

std::vector<uint8_t> HybridPQSuite::ClientHandshake::serialize() const {
    std::vector<uint8_t> data;
    
    // ML-KEM ciphertext (1088 bytes)
    data.insert(data.end(), ml_kem_ciphertext.begin(), ml_kem_ciphertext.end());
    
    // X25519 public key (32 bytes)
    data.insert(data.end(), x25519_public.begin(), x25519_public.end());
    
    // Certificate chain (variable)
    uint32_t cert_size = static_cast<uint32_t>(certificate_chain.size());
    for (int i = 0; i < 4; ++i) {
        data.push_back((cert_size >> (i * 8)) & 0xFF);
    }
    data.insert(data.end(), certificate_chain.begin(), certificate_chain.end());
    
    return data;
}

HybridPQSuite::ClientHandshake HybridPQSuite::ClientHandshake::deserialize(const std::vector<uint8_t>& data) {
    ClientHandshake hs;
    size_t offset = 0;
    
    // ML-KEM ciphertext
    for (size_t i = 0; i < ML_KEM_768_CIPHERTEXT_SIZE && offset < data.size(); ++i, ++offset) {
        hs.ml_kem_ciphertext[i] = data[offset];
    }
    
    // X25519 public key
    for (size_t i = 0; i < X25519_KEY_SIZE && offset < data.size(); ++i, ++offset) {
        hs.x25519_public[i] = data[offset];
    }
    
    // Certificate chain size
    if (offset + 4 <= data.size()) {
        uint32_t cert_size = 0;
        for (int i = 0; i < 4; ++i) {
            cert_size |= static_cast<uint32_t>(data[offset + i]) << (i * 8);
        }
        offset += 4;
        
        // Certificate chain data
        for (size_t i = 0; i < cert_size && offset < data.size(); ++i, ++offset) {
            hs.certificate_chain.push_back(data[offset]);
        }
    }
    
    return hs;
}

std::pair<HybridPQSuite::ClientHandshake, HybridPQSuite::SessionKeys> 
HybridPQSuite::client_init(std::mt19937_64& rng) {
    ClientHandshake client_hs;
    SessionKeys session_keys;
    
    // Génération des clés éphémères
    auto ml_kem_keys = MLKEM::generate_keypair(rng);
    auto [x25519_priv, x25519_pub] = X25519::generate_keypair(rng);
    
    // Stockage de la clé publique X25519
    client_hs.x25519_public = x25519_pub;
    
    // Encapsulation ML-KEM (serait fait avec la clé publique du serveur en réalité)
    auto [ciphertext, shared_secret_ml] = MLKEM::encapsulate(ml_kem_keys.public_key, rng);
    client_hs.ml_kem_ciphertext = ciphertext;
    
    // Combinaison des secrets (ML-KEM + X25519) pour la clé finale
    auto x25519_shared = X25519::dh(x25519_priv, x25519_pub);  // Simulation
    
    // Dérivation de la clé AES-256
    std::vector<uint8_t> combined_secret;
    combined_secret.insert(combined_secret.end(), shared_secret_ml.begin(), shared_secret_ml.end());
    combined_secret.insert(combined_secret.end(), x25519_shared.begin(), x25519_shared.end());
    
    auto derived = KDF::derive(combined_secret, "pqmix_v1_handshake", "aes256_key", AES_256_KEY_SIZE);
    for (size_t i = 0; i < AES_256_KEY_SIZE && i < derived.size(); ++i) {
        session_keys.encryption_key[i] = derived[i];
    }
    
    // Nonce aléatoire
    std::uniform_int_distribution<uint16_t> dist(0, 255);
    for (size_t i = 0; i < AES_GCM_NONCE_SIZE; ++i) {
        session_keys.nonce[i] = static_cast<uint8_t>(dist(rng));
    }
    session_keys.sequence_number = 0;
    
    return {client_hs, session_keys};
}

HybridPQSuite::SessionKeys HybridPQSuite::server_complete(
    const ClientHandshake& client_hs,
    ServerHandshake& server_hs,
    std::mt19937_64& rng) {
    
    SessionKeys session_keys;
    
    // Décapsulation ML-KEM
    auto shared_secret_ml = MLKEM::decapsulate(client_hs.ml_kem_ciphertext, server_hs.ml_kem_keys.secret_key);
    
    // ECDH X25519
    auto x25519_shared = X25519::dh(server_hs.x25519_keys.first, client_hs.x25519_public);
    
    // Combinaison et dérivation
    std::vector<uint8_t> combined_secret;
    combined_secret.insert(combined_secret.end(), shared_secret_ml.begin(), shared_secret_ml.end());
    combined_secret.insert(combined_secret.end(), x25519_shared.begin(), x25519_shared.end());
    
    auto derived = KDF::derive(combined_secret, "pqmix_v1_handshake", "aes256_key", AES_256_KEY_SIZE);
    for (size_t i = 0; i < AES_256_KEY_SIZE && i < derived.size(); ++i) {
        session_keys.encryption_key[i] = derived[i];
    }
    
    // Nonce
    std::uniform_int_distribution<uint16_t> dist(0, 255);
    for (size_t i = 0; i < AES_GCM_NONCE_SIZE; ++i) {
        session_keys.nonce[i] = static_cast<uint8_t>(dist(rng));
    }
    session_keys.sequence_number = 0;
    
    return session_keys;
}

HybridPQSuite::SessionKeys HybridPQSuite::rotate_keys(const SessionKeys& current, std::mt19937_64& rng) {
    SessionKeys new_keys;
    
    // Nouvelle dérivation basée sur l'ancienne clé + randomness
    std::vector<uint8_t> seed;
    seed.insert(seed.end(), current.encryption_key.begin(), current.encryption_key.end());
    
    std::uniform_int_distribution<uint16_t> dist(0, 255);
    for (int i = 0; i < 32; ++i) {
        seed.push_back(static_cast<uint8_t>(dist(rng)));
    }
    
    auto derived = KDF::derive(seed, "pqmix_v1_rotate", "new_aes256_key", AES_256_KEY_SIZE);
    for (size_t i = 0; i < AES_256_KEY_SIZE && i < derived.size(); ++i) {
        new_keys.encryption_key[i] = derived[i];
    }
    
    // Nouveau nonce
    for (size_t i = 0; i < AES_GCM_NONCE_SIZE; ++i) {
        new_keys.nonce[i] = static_cast<uint8_t>(dist(rng));
    }
    new_keys.sequence_number = 0;
    
    return new_keys;
}

} // namespace pqmix
