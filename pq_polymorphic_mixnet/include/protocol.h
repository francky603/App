#ifndef PROTOCOL_H
#define PROTOCOL_H

#include <vector>
#include <string>
#include <memory>
#include <optional>
#include <functional>
#include <chrono>
#include "crypto_pqc.h"
#include "polymorphic_engine.h"
#include "mixnet_node.h"

namespace pqmix {

/**
 * @brief Types de messages du protocole
 */
enum class MessageType : uint8_t {
    CLIENT_HELLO = 0x01,
    SERVER_HELLO = 0x02,
    KEY_EXCHANGE = 0x03,
    AUTH_REQUEST = 0x04,
    AUTH_RESPONSE = 0x05,
    DATA_MESSAGE = 0x10,
    COVER_TRAFFIC = 0x11,
    RENEGOTIATE = 0x20,
    CIRCUIT_ROTATE = 0x21,
    MODE_SWITCH = 0x22,
    HEARTBEAT = 0x30,
    ERROR = 0xFF
};

/**
 * @brief En-tête de message avec OID Kyber pour détection PQC
 */
struct ProtocolHeader {
    uint8_t magic[4] = {'P', 'Q', 'M', 'X'};  // Magic bytes PQMX
    uint8_t version = 0x01;
    MessageType type;
    uint16_t payload_size;
    uint32_t sequence_number;
    uint8_t flags = 0x00;
    // Bit 0: PQC enabled (OID Kyber 0x6399 present)
    // Bit 1: Polymorphic padding active
    // Bit 2: Cover traffic mode
    // Bit 3: Circuit rotation requested
    
    std::vector<uint8_t> serialize() const;
    static std::optional<ProtocolHeader> deserialize(const std::vector<uint8_t>& data);
    
    bool has_pqc_oid() const { return (flags & 0x01) != 0; }
    void set_pqc_oid(bool enabled) { 
        if (enabled) flags |= 0x01; 
        else flags &= ~0x01;
    }
};

/**
 * @brief Session cliente complète avec gestion PQC et polymorphisme
 */
class ClientSession {
public:
    using MessageCallback = std::function<void(const std::vector<uint8_t>&)>;
    using StateCallback = std::function<void(const std::string&)>;

    enum class State {
        DISCONNECTED,
        CONNECTING,
        HANDSHAKE_PQC,
        AUTHENTICATING,
        ACTIVE,
        RENEGOTIATING,
        ERROR
    };

    ClientSession(std::mt19937_64& rng);
    ~ClientSession();

    /**
     * @brief Initialise la connexion avec handshake PQC hybride
     * Génère un Client Hello avec OID Kyber 0x6399
     * @param server_address Adresse du serveur
     * @return Données à envoyer au serveur
     */
    std::vector<uint8_t> initiate_connection(const std::string& server_address);
    
    /**
     * @brief Traite la réponse du serveur (Server Hello + clés publiques)
     * @param server_data Données reçues du serveur
     * @return Données de confirmation à envoyer
     */
    std::vector<uint8_t> complete_handshake(const std::vector<uint8_t>& server_data);
    
    /**
     * @brief Envoie un message utilisateur via le Mixnet
     * Le message est encapsulé dans un oignon avec padding polymorphique
     * @param message Message en clair
     * @return Paquet final à transmettre
     */
    std::vector<uint8_t> send_message(const std::vector<uint8_t>& message);
    
    /**
     * @brief Reçoit et déchiffre un message du serveur
     * @param encrypted_data Données chiffrées reçues
     * @return Message déchiffré ou nullopt si erreur
     */
    std::optional<std::vector<uint8_t>> receive_message(const std::vector<uint8_t>& encrypted_data);
    
    /**
     * @brief Génère du trafic de couverture pendant les périodes idle
     * Empêche les silences > 1 seconde
     * @return Paquet de cover traffic
     */
    std::vector<uint8_t> generate_idle_traffic();
    
    /**
     * @brief Demande une renégociation des clés (rotation < 10 min)
     * @return Message de renégociation à envoyer
     */
    std::vector<uint8_t> request_renegotiation();
    
    /**
     * @brief Change le mode protocolaire dynamiquement
     * @param new_mode Nouveau mode (WebRTC, HTTP2, White Noise, etc.)
     * @return Message de switch de mode
     */
    std::vector<uint8_t> switch_protocol_mode(ProtocolMode new_mode);
    
    /**
     * @brief Force la rotation du circuit Mixnet
     * @return Message de rotation
     */
    std::vector<uint8_t> rotate_circuit();
    
    /**
     * @brief Obtient l'état actuel de la session
     */
    State get_state() const { return state_; }
    
    /**
     * @brief Vérifie si la session est active et sécurisée (PQC validé)
     */
    bool is_secure() const;
    
    /**
     * @brief Obtient les statistiques de trafic polymorphique
     */
    const TrafficStats& get_traffic_stats() const;

private:
    std::mt19937_64& rng_;
    State state_;
    
    HybridPQSuite::SessionKeys session_keys_;
    HybridPQSuite::ClientHandshake client_handshake_;
    HybridPQSuite::ServerHandshake server_handshake_;
    
    std::unique_ptr<MixnetNetwork> mixnet_;
    std::unique_ptr<PolymorphicEngine> poly_engine_;
    
    std::chrono::steady_clock::time_point last_key_rotation_;
    std::chrono::steady_clock::time_point last_circuit_rotation_;
    std::chrono::steady_clock::time_point last_packet_sent_;
    
    uint64_t sequence_number_ = 0;
    std::string server_address_;
    
    // Callbacks
    MessageCallback on_message_;
    StateCallback on_state_change_;
    
    void setState(State new_state);
    void check_key_rotation();
    void check_circuit_rotation();
    std::vector<uint8_t> encrypt_payload(const std::vector<uint8_t>& plaintext);
    std::vector<uint8_t> decrypt_payload(const std::vector<uint8_t>& ciphertext);
};

/**
 * @brief Session serveur avec support multi-clients
 */
class ServerSession {
public:
    using ClientCallback = std::function<void(const std::string&, const std::vector<uint8_t>&)>;
    using DisconnectCallback = std::function<void(const std::string&)>;

    ServerSession(std::mt19937_64& rng);
    
    /**
     * @brief Initialise le serveur avec ses clés PQC
     * @return Clés publiques à distribuer
     */
    std::vector<uint8_t> initialize_server();
    
    /**
     * @brief Traite un Client Hello et répond avec Server Hello
     * Sélectionne aléatoirement une suite cryptographique parmi 9 options
     * @param client_hello Données du client
     * @param client_id Identifiant unique du client
     * @return Réponse Server Hello avec clés publiques
     */
    std::vector<uint8_t> handle_client_hello(const std::vector<uint8_t>& client_hello,
                                              const std::string& client_id);
    
    /**
     * @brief Complète le handshake PQC après réception du KEM client
     * @param kem_data Données KEM du client
     * @param client_id Identifiant du client
     * @return Confirmation de session établie
     */
    std::vector<uint8_t> complete_handshake(const std::vector<uint8_t>& kem_data,
                                             const std::string& client_id);
    
    /**
     * @brief Traite un message reçu d'un client
     * @param client_id Identifiant du client
     * @param encrypted_data Données chiffrées
     * @return Réponse optionnelle
     */
    std::optional<std::vector<uint8_t>> handle_message(const std::string& client_id,
                                                        const std::vector<uint8_t>& encrypted_data);
    
    /**
     * @brief Déconnecte un client
     */
    void disconnect_client(const std::string& client_id);
    
    /**
     * @brief Diffuse un message à tous les clients connectés
     */
    void broadcast_to_all(const std::vector<uint8_t>& message);
    
    /**
     * @brief Obtient le nombre de clients connectés
     */
    size_t get_client_count() const { return clients_.size(); }
    
    /**
     * @brief Statistiques globales du serveur
     */
    struct ServerStats {
        size_t total_connections = 0;
        size_t pqc_handshakes_completed = 0;
        size_t circuits_rotated = 0;
        size_t mode_switches = 0;
        std::map<ProtocolMode, size_t> active_modes;
    };
    
    const ServerStats& get_stats() const { return stats_; }

private:
    std::mt19937_64& rng_;
    
    struct ClientContext {
        std::string id;
        HybridPQSuite::SessionKeys keys;
        HybridPQSuite::ServerHandshake handshake;
        std::unique_ptr<MixnetNetwork> mixnet;
        std::unique_ptr<PolymorphicEngine> poly_engine;
        std::chrono::steady_clock::time_point connected_at;
        std::chrono::steady_clock::time_point last_activity;
        ProtocolMode current_mode;
        uint64_t sequence_number;
        bool is_authenticated = false;
    };
    
    std::map<std::string, std::unique_ptr<ClientContext>> clients_;
    HybridPQSuite::ServerHandshake server_handshake_;
    ServerStats stats_;
    
    ClientCallback on_client_message_;
    DisconnectCallback on_client_disconnect_;
    
    uint8_t select_crypto_suite();  // Retourne index 0-8 pour les 9 suites
};

/**
 * @brief Utilitaires de sérialisation/désérialisation
 */
class Serialization {
public:
    template<typename T>
    static std::vector<uint8_t> write_uint(const std::vector<uint8_t>& data, T value) {
        std::vector<uint8_t> result = data;
        for (size_t i = 0; i < sizeof(T); ++i) {
            result.push_back((value >> (i * 8)) & 0xFF);
        }
        return result;
    }
    
    template<typename T>
    static T read_uint(const std::vector<uint8_t>& data, size_t offset) {
        T value = 0;
        for (size_t i = 0; i < sizeof(T) && offset + i < data.size(); ++i) {
            value |= static_cast<T>(data[offset + i]) << (i * 8);
        }
        return value;
    }
    
    static std::vector<uint8_t> concat(const std::vector<std::vector<uint8_t>>& buffers);
};

} // namespace pqmix

#endif // PROTOCOL_H
