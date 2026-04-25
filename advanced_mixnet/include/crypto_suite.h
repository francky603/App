/**
 * @file crypto_suite.h
 * @brief Interface abstraite pour les suites cryptographiques
 * 
 * Définit l'interface commune que toutes les 9 suites cryptographiques
 * doivent implémenter pour le système Mixnet.
 */

#ifndef CRYPTO_SUITE_H
#define CRYPTO_SUITE_H

#include "crypto_types.h"
#include <memory>
#include <functional>

namespace mixnet {
namespace crypto {

/**
 * @brief Interface abstraite pour une suite cryptographique complète
 * 
 * Chaque suite implémente:
 * - Échange de clés (KEM ou ECDH)
 * - Chiffrement symétrique AEAD
 * - Dérivation de clés
 * - Signature/Verification (optionnel)
 */
class ICryptoSuite {
public:
    virtual ~ICryptoSuite() = default;
    
    // =========================================================================
    // Informations sur la suite
    // =========================================================================
    
    /**
     * @brief Retourne l'identifiant de la suite
     */
    virtual CryptoSuiteID get_id() const = 0;
    
    /**
     * @brief Retourne les informations descriptives de la suite
     */
    virtual SuiteInfo get_info() const = 0;
    
    /**
     * @brief Nom lisible de la suite
     */
    virtual std::string get_name() const = 0;
    
    // =========================================================================
    // Génération de clés (Key Exchange)
    // =========================================================================
    
    /**
     * @brief Génère une paire de clés pour l'échange
     * @return Résultat contenant clé publique et privée
     */
    virtual KeyExchangeResult generate_keypair() = 0;
    
    /**
     * @brief Effectue un échange de clés pour établir un secret partagé
     * @param private_key Clé privée locale
     * @param peer_public_key Clé publique du pair
     * @return Secret partagé de 32 bytes
     */
    virtual std::array<uint8_t, SHARED_SECRET_SIZE> derive_shared_secret(
        const std::vector<uint8_t>& private_key,
        const std::vector<uint8_t>& peer_public_key
    ) = 0;
    
    /**
     * @brief Encapsulation KEM (pour les suites PQC)
     * @param peer_public_key Clé publique du destinataire
     * @return Ciphertext et secret partagé
     */
    virtual KeyExchangeResult kem_encapsulate(
        const std::vector<uint8_t>& peer_public_key
    ) = 0;
    
    /**
     * @brief Décapsulation KEM (pour les suites PQC)
     * @param private_key Clé privée locale
     * @param ciphertext Ciphertext reçu
     * @return Secret partagé ou échec
     */
    virtual std::optional<std::array<uint8_t, SHARED_SECRET_SIZE>> kem_decapsulate(
        const std::vector<uint8_t>& private_key,
        const std::vector<uint8_t>& ciphertext
    ) = 0;
    
    // =========================================================================
    // Chiffrement Symétrique AEAD
    // =========================================================================
    
    /**
     * @brief Chiffre un message avec authentification
     * @param key Clé symétrique
     * @param plaintext Données à chiffrer
     * @param aad Données additionnelles authentifiées
     * @return Nonce + ciphertext + tag
     */
    virtual AEADCiphertext encrypt(
        const SymmetricKey& key,
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& aad = {}
    ) = 0;
    
    /**
     * @brief Déchiffre un message avec vérification d'authentification
     * @param key Clé symétrique
     * @param nonce Nonce utilisé pour le chiffrement
     * @param ciphertext Données chiffrées
     * @param tag Tag d'authentification
     * @param aad Données additionnelles authentifiées
     * @return Plaintext déchiffré ou nullopt si vérification échoue
     */
    virtual std::optional<std::vector<uint8_t>> decrypt(
        const SymmetricKey& key,
        const Nonce& nonce,
        const std::vector<uint8_t>& ciphertext,
        const AuthTag& tag,
        const std::vector<uint8_t>& aad = {}
    ) = 0;
    
    // =========================================================================
    // Dérivation de clés
    // =========================================================================
    
    /**
     * @brief Derive une clé symétrique à partir d'un secret partagé
     * @param shared_secret Secret issu de l'échange de clés
     * @param context Contexte de dérivation (label, etc.)
     * @return Clé symétrique dérivée
     */
    virtual SymmetricKey derive_symmetric_key(
        const std::array<uint8_t, SHARED_SECRET_SIZE>& shared_secret,
        const std::string& context = ""
    ) = 0;
    
    // =========================================================================
    // Signatures (pour les suites avec ML-DSA)
    // =========================================================================
    
    /**
     * @brief Signe un message (si supporté par la suite)
     */
    virtual std::vector<uint8_t> sign(
        const std::vector<uint8_t>& private_key,
        const std::vector<uint8_t>& message
    ) {
        return {}; // Non supporté par défaut
    }
    
    /**
     * @brief Vérifie une signature (si supporté par la suite)
     */
    virtual bool verify(
        const std::vector<uint8_t>& public_key,
        const std::vector<uint8_t>& message,
        const std::vector<uint8_t>& signature
    ) {
        return false; // Non supporté par défaut
    }
    
    // =========================================================================
    // Utilitaires
    // =========================================================================
    
    /**
     * @brief Crée une nouvelle instance de la même suite
     */
    virtual std::unique_ptr<ICryptoSuite> clone() const = 0;
    
    /**
     * @brief Réinitialise l'état de la suite
     */
    virtual void reset() = 0;
};

/**
 * @brief Factory pour créer des suites cryptographiques
 */
class CryptoSuiteFactory {
public:
    /**
     * @brief Crée une suite spécifique par ID
     */
    static std::unique_ptr<ICryptoSuite> create_suite(CryptoSuiteID id);
    
    /**
     * @brief Crée une suite aléatoire parmi les 9 disponibles
     */
    static std::unique_ptr<ICryptoSuite> create_random_suite();
    
    /**
     * @brief Liste toutes les suites disponibles
     */
    static std::vector<SuiteInfo> get_all_suites();
    
    /**
     * @brief Obtient les infos d'une suite spécifique
     */
    static SuiteInfo get_suite_info(CryptoSuiteID id);
};

} // namespace crypto
} // namespace mixnet

#endif // CRYPTO_SUITE_H
