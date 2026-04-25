/**
 * @file blockchain.h
 * @brief Blockchain intégrée pour l'audit des messages Mixnet
 * 
 * Implémente une chaîne de blocs toujours active pour tracer
 * et auditer tous les messages transitant par le réseau.
 */

#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

#include "crypto_types.h"
#include <vector>
#include <string>
#include <mutex>
#include <atomic>
#include <functional>

namespace mixnet {
namespace blockchain {

/**
 * @brief Structure d'un bloc dans la chaîne
 */
struct Block {
    uint64_t index;                    // Position dans la chaîne
    uint64_t timestamp;                // UTC timestamp en millisecondes
    std::string message_hash;          // SHA256 du message (hex)
    std::string sender;                // ID expéditeur
    std::string receiver;              // ID destinataire
    std::string message_content;       // Contenu (optionnellement chiffré)
    std::string previous_hash;         // Hash du bloc précédent (hex)
    std::string current_hash;          // Hash SHA256 de ce bloc (hex)
    uint64_t nonce;                    // Preuve de travail
    
    Block();
    Block(uint64_t idx, const std::string& prev_hash);
    
    /**
     * @brief Calcule le hash actuel du bloc
     */
    std::string calculate_hash() const;
    
    /**
     * @brief Vérifie si le hash est valide (Proof of Work)
     * @param difficulty Nombre de zéros requis en début de hash
     */
    bool verify_hash(size_t difficulty) const;
    
    /**
     * @brief Mine le bloc pour satisfaire la difficulté
     * @param difficulty Nombre de zéros requis
     */
    void mine(size_t difficulty);
};

/**
 * @brief Chaîne de blocs Mixnet
 * 
 * Caractéristiques:
 * - Mining continu en arrière-plan (toutes les 5 secondes)
 * - Difficulté ajustable
 * - Validation automatique
 * - Thread-safe
 */
class MixnetBlockchain {
public:
    /**
     * @brief Message en attente de minage
     */
    struct PendingMessage {
        std::string sender;
        std::string receiver;
        std::string content;
        uint64_t timestamp;
        
        PendingMessage(const std::string& s, const std::string& r, const std::string& c)
            : sender(s), receiver(r), content(c), timestamp(get_current_timestamp()) {}
            
    private:
        static uint64_t get_current_timestamp();
    };
    
    MixnetBlockchain(size_t difficulty = 2);
    ~MixnetBlockchain() = default;
    
    // =========================================================================
    // Gestion de la chaîne
    // =========================================================================
    
    /**
     * @brief Initialise la chaîne avec un bloc de genèse
     */
    void initialize();
    
    /**
     * @brief Ajoute un message à miner
     */
    void add_pending_message(const std::string& sender, 
                            const std::string& receiver,
                            const std::string& content);
    
    /**
     * @brief Mine tous les messages en attente
     * @return Nombre de blocs créés
     */
    size_t mine_pending();
    
    /**
     * @brief Ajoute un bloc directement (pour tests/sync)
     */
    bool add_block(Block block);
    
    /**
     * @brief Vérifie la validité de toute la chaîne
     */
    bool verify_chain() const;
    
    // =========================================================================
    // Informations et statistiques
    // =========================================================================
    
    /**
     * @brief Retourne la longueur de la chaîne
     */
    size_t get_chain_length() const;
    
    /**
     * @brief Retourne le dernier bloc
     */
    const Block* get_latest_block() const;
    
    /**
     * @brief Retourne un bloc par index
     */
    const Block* get_block(size_t index) const;
    
    /**
     * @brief Statistiques sur les messages en attente
     */
    struct BlockchainStatus {
        size_t chain_length;
        size_t pending_count;
        size_t difficulty;
        uint64_t last_mine_time;
        bool is_mining;
    };
    
    BlockchainStatus get_status() const;
    
    /**
     * @brief Définit la difficulté de minage
     */
    void set_difficulty(size_t difficulty);
    
    /**
     * @brief Obtient la difficulté actuelle
     */
    size_t get_difficulty() const;
    
    // =========================================================================
    // Callbacks et événements
    // =========================================================================
    
    /**
     * @brief Callback appelé quand un bloc est miné
     */
    using OnBlockMinedCallback = std::function<void(const Block&)>;
    void set_on_block_mined(OnBlockMinedCallback callback);
    
    /**
     * @brief Démarrer/arrêter le mining automatique
     */
    void start_mining_loop();
    void stop_mining_loop();
    
private:
    std::vector<Block> chain_;
    std::vector<PendingMessage> pending_messages_;
    size_t difficulty_;
    mutable std::mutex mutex_;
    std::atomic<bool> mining_active_;
    std::atomic<uint64_t> last_mine_time_;
    OnBlockMinedCallback on_block_mined_;
    
    /**
     * @brief Hash SHA256 d'une chaîne
     */
    static std::string sha256(const std::string& input);
    
    /**
     * @brief Vérifie qu'un hash satisfait la difficulté
     */
    static bool hash_meets_difficulty(const std::string& hash, size_t difficulty);
};

} // namespace blockchain
} // namespace mixnet

#endif // BLOCKCHAIN_H
