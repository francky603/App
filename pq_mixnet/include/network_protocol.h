#ifndef NETWORK_PROTOCOL_H
#define NETWORK_PROTOCOL_H

#include <vector>
#include <string>
#include <cstdint>
#include <functional>
#include <memory>
#include "pqc_core.h"
#include "polymorphic_engine.h"
#include "mixnet_node.h"

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <errno.h>
#endif

namespace pq_mixnet {

// Types de messages du protocole
enum class MessageType : uint8_t {
    CLIENT_HELLO = 0x01,
    SERVER_HELLO = 0x02,
    KEY_EXCHANGE = 0x03,
    AUTH_REQUEST = 0x04,
    AUTH_RESPONSE = 0x05,
    DATA_MESSAGE = 0x06,
    COVER_TRAFFIC = 0x07,
    RENEGOTIATE = 0x08,
    CIRCUIT_ROTATE = 0x09,
    HEARTBEAT = 0x0A,
    SHUTDOWN = 0xFF
};

// En-tête de message polymorphe
struct MessageHeader {
    MessageType type;
    uint16_t size;
    uint32_t sequence;
    uint64_t timestamp;
    std::array<uint8_t, 16> nonce;  // Nonce aléatoire
};

// État de la session
struct SessionState {
    bool connected;
    bool authenticated;
    HybridKeyPair local_keys;
    HybridKeyPair remote_keys;
    std::array<uint8_t, 32> shared_secret;
    uint32_t sequence_number;
    uint64_t last_activity;
    ProtocolMode current_mode;
    MixCircuit active_circuit;
    bool needs_rotation;
};

class NetworkProtocol {
public:
    NetworkProtocol();
    ~NetworkProtocol();
    
    // Initialisation réseau
    bool initialize(int port);
    
    // Connexion client au serveur
    bool connect(const std::string& host, int port);
    
    // Démarrage serveur
    bool startServer(int port);
    
    // Handshake post-quantique hybride
    bool performHandshake(bool is_client);
    
    // Envoyer un message chiffré et polymorphe
    bool sendMessage(const std::vector<uint8_t>& data);
    
    // Recevoir un message
    std::vector<uint8_t> receiveMessage();
    
    // Générer et envoyer du trafic de couverture
    void sendCoverTraffic();
    
    // Renégociation seamless des clés
    bool renegotiateKeys();
    
    // Rotation du circuit mixnet
    bool rotateCircuit();
    
    // Vérifier l'état de la session
    const SessionState& getSessionState() const { return session_; }
    
    // Obtenir les statistiques de trafic
    TrafficStats getTrafficStats() const;
    
    // Modifier l'état de la session (pour tests)
    void setConnected(bool c) { session_.connected = c; }
    void setAuthenticated(bool a) { session_.authenticated = a; }
    
    // Arrêter proprement
    void shutdown();
    
private:
    PqcCore pqc_core_;
    PolymorphicEngine poly_engine_;
    SessionState session_;
    
#ifdef _WIN32
    SOCKET listen_socket_;
    SOCKET client_socket_;
#else
    int listen_socket_;
    int client_socket_;
#endif
    
    std::mt19937_64 rng_;
    
    // Fonctions internes
    MessageHeader createHeader(MessageType type, size_t payload_size);
    std::vector<uint8_t> encryptMessage(const std::vector<uint8_t>& data);
    std::vector<uint8_t> decryptMessage(const std::vector<uint8_t>& encrypted);
    PolymorphicPacket wrapInPolymorphicPacket(const std::vector<uint8_t>& data);
    void maintainCoverTraffic();
    bool validateHandshake(const std::vector<uint8_t>& hello_data);
    
    // Buffer pour les messages en attente
    std::vector<uint8_t> recv_buffer_;
};

// Factory pour créer client ou serveur
class NetworkFactory {
public:
    static std::unique_ptr<NetworkProtocol> createClient();
    static std::unique_ptr<NetworkProtocol> createServer(int port);
};

} // namespace pq_mixnet

#endif // NETWORK_PROTOCOL_H
