/**
 * @file mix_session.h
 * @brief Gestion des sessions Mixnet avec renégociation seamless
 * 
 * Implémente une session de communication qui ne s'interrompt JAMAIS,
 * même pendant la renégociation cryptographique.
 */

#ifndef MIX_SESSION_H
#define MIX_SESSION_H

#include "crypto_suite.h"
#include "blockchain.h"
#include <queue>
#include <condition_variable>
#include <thread>
#include <chrono>

namespace mixnet {
namespace session {

/**
 * @brief Configuration d'une session
 */
struct SessionConfig {
    std::string client_id;
    std::string server_id;
    uint64_t session_timeout_ms = 300000;  // 5 minutes
    uint64_t renegotiation_interval_ms = 60000;  // 1 minute
    uint64_t ping_interval_ms = 1000;  // 1 seconde
    size_t max_pending_messages = 1000;
    bool enable_blockchain_audit = true;
};

/**
 * @brief Statistiques de session
 */
struct SessionStats {
    uint64_t messages_sent;
    uint64_t messages_received;
    uint64_t bytes_sent;
    uint64_t bytes_received;
    uint64_t renegotiations_count;
    uint64_t last_renegotiation_time;
    uint64_t session_start_time;
    uint64_t last_activity_time;
    double average_latency_ms;
    crypto::CryptoSuiteID current_suite;
    bool is_authenticated;
    bool is_active;
    
    SessionStats() 
        : messages_sent(0), messages_received(0)
        , bytes_sent(0), bytes_received(0)
        , renegotiations_count(0), last_renegotiation_time(0)
        , session_start_time(0), last_activity_time(0)
        , average_latency_ms(0.0), current_suite(crypto::CryptoSuiteID::INVALID)
        , is_authenticated(false), is_active(false) {}
};

/**
 * @brief Message en attente d'envoi
 */
struct PendingMessage {
    crypto::MessageType type;
    std::vector<uint8_t> data;
    uint64_t sequence_number;
    uint64_t timestamp;
    bool urgent;  // Messages de renégociation sont urgents
    
    PendingMessage(crypto::MessageType t, const std::vector<uint8_t>& d, bool u = false)
        : type(t), data(d), sequence_number(0), timestamp(get_timestamp()), urgent(u) {}
        
private:
    static uint64_t get_timestamp();
};

/**
 * @brief Session Mixnet avec communication continue
 * 
 * Garanties:
 * - Communication NEVER interrompue (tokio::select! equivalent)
 * - Renégociation seamless (<30ms)
 * - Blockchain mining indépendant et continu
 * - Forward secrecy garantie
 */
class MixSession {
public:
    /**
     * @brief Callback pour recevoir des messages
     */
    using MessageCallback = std::function<void(
        crypto::MessageType type,
        const std::vector<uint8_t>& data,
        uint64_t sequence_number
    )>;
    
    /**
     * @brief Callback pour les événements de session
     */
    using EventCallback = std::function<void(
        const std::string& event,
        const std::string& details
    )>;
    
    MixSession(const SessionConfig& config);
    ~MixSession();
    
    // =========================================================================
    // Cycle de vie
    // =========================================================================
    
    /**
     * @brief Initialise la session avec une suite cryptographique
     */
    bool initialize(crypto::CryptoSuiteID suite_id);
    
    /**
     * @brief Démarre la boucle de communication principale
     */
    void start_communication_loop();
    
    /**
     * @brief Arrête proprement la session
     */
    void shutdown();
    
    /**
     * @brief Vérifie si la session est active
     */
    bool is_active() const;
    
    // =========================================================================
    // Envoi de messages
    // =========================================================================
    
    /**
     * @brief Envoie un message chiffré
     * @return true si envoyé avec succès (ou mis en file d'attente)
     */
    bool send_message(crypto::MessageType type, const std::vector<uint8_t>& data);
    
    /**
     * @brief Envoie un message texte (wrapper utilitaire)
     */
    bool send_text_message(const std::string& text);
    
    /**
     * @brief Envoie un ping de maintien de session
     */
    bool send_ping();
    
    /**
     * @brief Envoie tous les messages en attente
     */
    void flush_pending_messages();
    
    // =========================================================================
    // Réception de messages
    // =========================================================================
    
    /**
     * @brief Définit le callback de réception
     */
    void set_message_callback(MessageCallback callback);
    
    /**
     * @brief Traite un message reçu (appelé par le réseau)
     */
    void handle_incoming_message(const std::vector<uint8_t>& encrypted_data);
    
    // =========================================================================
    // Renégociation Cryptographique
    // =========================================================================
    
    /**
     * @brief Déclenche une renégociation de suite cryptographique
     * 
     * GARANTIE: La communication CONTINUE pendant toute la procédure
     * Durée typique: <30ms
     */
    bool initiate_renegotiation(crypto::CryptoSuiteID new_suite_id);
    
    /**
     * @brief Traite une demande de renégociation reçue
     */
    void handle_renegotiation_request(const std::vector<uint8_t>& data);
    
    /**
     * @brief Force une renégociation immédiate (détection d'attaque)
     */
    void force_emergency_renegotiation();
    
    // =========================================================================
    // Authentification
    // =========================================================================
    
    /**
     * @brief Authentifie la session avec username/password
     */
    bool authenticate(const std::string& username, const std::string& password_hash);
    
    /**
     * @brief Vérifie si la session est authentifiée
     */
    bool is_authenticated() const;
    
    // =========================================================================
    // Blockchain Integration
    // =========================================================================
    
    /**
     * @brief Ajoute un message à la blockchain pour audit
     */
    void add_to_blockchain(const std::string& sender,
                          const std::string& receiver,
                          const std::string& content);
    
    /**
     * @brief Obtient une référence à la blockchain
     */
    blockchain::MixnetBlockchain* get_blockchain();
    
    // =========================================================================
    // Statistiques et Informations
    // =========================================================================
    
    /**
     * @brief Obtient les statistiques de session
     */
    SessionStats get_stats() const;
    
    /**
     * @brief Obtient la suite cryptographique actuelle
     */
    crypto::CryptoSuiteID get_current_suite() const;
    
    /**
     * @brief Obtient les informations de la suite actuelle
     */
    crypto::SuiteInfo get_suite_info() const;
    
    /**
     * @brief Définit le callback d'événements
     */
    void set_event_callback(EventCallback callback);
    
    // =========================================================================
    // Configuration
    // =========================================================================
    
    /**
     * @brief Met à jour la configuration de session
     */
    void update_config(const SessionConfig& config);
    
    /**
     * @brief Définit l'intervalle de renégociation automatique
     */
    void set_renegotiation_interval(uint64_t interval_ms);
    
private:
    SessionConfig config_;
    std::unique_ptr<crypto::ICryptoSuite> current_suite_;
    crypto::SymmetricKey current_key_;
    std::atomic<bool> is_active_;
    std::atomic<bool> is_authenticating_;
    std::atomic<bool> is_renegotiating_;
    
    std::queue<PendingMessage> pending_messages_;
    mutable std::mutex pending_mutex_;
    std::condition_variable pending_cv_;
    
    std::atomic<uint64_t> send_sequence_;
    std::atomic<uint64_t> recv_sequence_;
    
    SessionStats stats_;
    mutable std::mutex stats_mutex_;
    
    std::unique_ptr<blockchain::MixnetBlockchain> blockchain_;
    
    MessageCallback message_callback_;
    EventCallback event_callback_;
    
    std::thread communication_thread_;
    std::thread renegotiation_check_thread_;
    std::atomic<bool> threads_running_;
    
    // État temporaire pour renégociation
    std::unique_ptr<crypto::ICryptoSuite> next_suite_;
    crypto::SymmetricKey next_key_;
    std::mutex key_switch_mutex_;
    
    // =========================================================================
    // Méthodes internes
    // =========================================================================
    
    /**
     * @brief Boucle principale de communication (équivalent tokio::select!)
     */
    void communication_loop();
    
    /**
     * @brief Vérifie périodiquement si une renégociation est nécessaire
     */
    void renegotiation_check_loop();
    
    /**
     * @brief Chiffre un message avec la clé actuelle
     */
    crypto::EncryptedMessage encrypt_message(
        crypto::MessageType type,
        const std::vector<uint8_t>& plaintext
    );
    
    /**
     * @brief Déchiffre un message reçu
     */
    std::optional<std::vector<uint8_t>> decrypt_message(
        const crypto::EncryptedMessage& encrypted
    );
    
    /**
     * @brief Bascule vers la nouvelle clé après renégociation
     */
    void switch_to_new_key();
    
    /**
     * @brief Émet un événement
     */
    void emit_event(const std::string& event, const std::string& details);
    
    /**
     * @brief Génère une nouvelle paire de clés pour renégociation
     */
    crypto::KeyExchangeResult generate_new_keypair();
};

} // namespace session
} // namespace mixnet

#endif // MIX_SESSION_H
