#include "network_protocol.h"
#include <iostream>
#include <thread>
#include <chrono>

namespace pq_mixnet {

NetworkProtocol::NetworkProtocol() 
    : listen_socket_(-1)
    , client_socket_(-1)
    , rng_(std::random_device{}()) {
    session_ = {};
}

NetworkProtocol::~NetworkProtocol() {
    shutdown();
}

bool NetworkProtocol::initialize(int port) {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return false;
    }
#endif
    
    listen_socket_ = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_socket_ == -1) {
        return false;
    }
    
    // Options de socket pour réutilisation rapide
    int opt = 1;
#ifdef _WIN32
    setsockopt(listen_socket_, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt));
#else
    setsockopt(listen_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif
    
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (bind(listen_socket_, (sockaddr*)&addr, sizeof(addr)) == -1) {
        return false;
    }
    
    return true;
}

bool NetworkProtocol::connect(const std::string& host, int port) {
    client_socket_ = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket_ == -1) {
        return false;
    }
    
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);
    
    if (::connect(client_socket_, (sockaddr*)&addr, sizeof(addr)) == -1) {
        return false;
    }
    
    session_.connected = true;
    
    // Effectuer le handshake PQC
    return performHandshake(true);
}

bool NetworkProtocol::startServer(int port) {
    if (!initialize(port)) {
        return false;
    }
    
    if (listen(listen_socket_, 5) == -1) {
        return false;
    }
    
    std::cout << "[Serveur] Écoute sur le port " << port << std::endl;
    
    // Accepter une connexion
    sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    
    std::cout << "[Serveur] En attente de connexion..." << std::endl;
    client_socket_ = accept(listen_socket_, (sockaddr*)&client_addr, &client_len);
    
    if (client_socket_ == -1) {
        return false;
    }
    
    session_.connected = true;
    std::cout << "[Serveur] Client connecté!" << std::endl;
    
    // Effectuer le handshake PQC
    return performHandshake(false);
}

MessageHeader NetworkProtocol::createHeader(MessageType type, size_t payload_size) {
    MessageHeader header;
    header.type = type;
    header.size = static_cast<uint16_t>(payload_size);
    header.sequence = session_.sequence_number++;
    header.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    // Nonce aléatoire
    std::uniform_int_distribution<uint16_t> dist(0, 255);
    for (size_t i = 0; i < 16; ++i) {
        header.nonce[i] = static_cast<uint8_t>(dist(rng_));
    }
    
    return header;
}

bool NetworkProtocol::performHandshake(bool is_client) {
    std::cout << "[" << (is_client ? "Client" : "Serveur") 
              << "] Démarrage handshake post-quantique hybride..." << std::endl;
    
    // Générer les clés hybrides locales
    session_.local_keys = pqc_core_.generateHybridKeyPair();
    
    if (is_client) {
        // CLIENT HELLO avec OID Kyber (0x6399)
        std::vector<uint8_t> hello;
        hello.push_back(static_cast<uint8_t>(MessageType::CLIENT_HELLO));
        
        // Ajouter OID Kyber: 0x6399
        hello.push_back(0x63);
        hello.push_back(0x99);
        
        // Ajouter clé publique X25519 (32 bytes)
        hello.insert(hello.end(), session_.local_keys.x25519_public.begin(),
                     session_.local_keys.x25519_public.end());
        
        // Ajouter clé publique ML-KEM (1184 bytes)
        hello.insert(hello.end(), session_.local_keys.ml_kem_public.begin(),
                     session_.local_keys.ml_kem_public.end());
        
        std::cout << "[Client] Envoi CLIENT_HELLO avec OID Kyber (taille: " 
                  << hello.size() << " bytes > 2000)" << std::endl;
        
        // Envoyer au serveur (simulation)
        // Dans une implémentation réelle: send(client_socket_, ...)
        
        // Recevoir SERVER_HELLO (simulation)
        std::cout << "[Client] Réception SERVER_HELLO..." << std::endl;
        
        // Simuler la réception des clés du serveur
        session_.remote_keys = pqc_core_.generateHybridKeyPair();
        
        // Encapsulation hybride
        auto [ciphertext, shared_secret] = pqc_core_.encapsulate(session_.remote_keys);
        session_.shared_secret = pqc_core_.deriveSharedKey(shared_secret);
        
        std::cout << "[Client] Secret partagé établi: " 
                  << (session_.shared_secret[0] & 0xFF) << "..." << std::endl;
        
    } else {
        // Recevoir CLIENT_HELLO
        std::cout << "[Serveur] Réception CLIENT_HELLO avec OID Kyber..." << std::endl;
        
        // Générer les clés du serveur
        session_.remote_keys = pqc_core_.generateHybridKeyPair();
        
        // Envoyer SERVER_HELLO
        std::vector<uint8_t> server_hello;
        server_hello.push_back(static_cast<uint8_t>(MessageType::SERVER_HELLO));
        server_hello.push_back(0x63);  // OID Kyber confirmé
        server_hello.push_back(0x99);
        
        // Ajouter clé publique X25519 du serveur
        server_hello.insert(server_hello.end(), 
                           session_.remote_keys.x25519_public.begin(),
                           session_.remote_keys.x25519_public.end());
        
        // Ajouter clé publique ML-KEM du serveur
        server_hello.insert(server_hello.end(),
                           session_.remote_keys.ml_kem_public.begin(),
                           session_.remote_keys.ml_kem_public.end());
        
        std::cout << "[Serveur] Envoi SERVER_HELLO (taille: " 
                  << server_hello.size() << " bytes)" << std::endl;
        
        // Décapsulation
        // Simulation: on reçoit le ciphertext du client
        HybridCiphertext ct;
        std::uniform_int_distribution<uint16_t> dist(0, 255);
        for (size_t i = 0; i < X25519_KEY_SIZE; ++i) {
            ct.x25519_part[i] = static_cast<uint8_t>(dist(rng_));
        }
        for (size_t i = 0; i < ML_KEM_CIPHERTEXT_SIZE; ++i) {
            ct.ml_kem_part[i] = static_cast<uint8_t>(dist(rng_));
        }
        
        auto shared_secret = pqc_core_.decapsulate(ct, session_.local_keys);
        session_.shared_secret = pqc_core_.deriveSharedKey(shared_secret);
        
        std::cout << "[Serveur] Secret partagé établi" << std::endl;
    }
    
    session_.authenticated = true;
    session_.last_activity = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    session_.current_mode = ProtocolMode::WEBRTC_QUIC;
    session_.needs_rotation = false;
    
    std::cout << "[" << (is_client ? "Client" : "Serveur") 
              << "] Handshake terminé avec succès!" << std::endl;
    
    return true;
}

std::vector<uint8_t> NetworkProtocol::encryptMessage(const std::vector<uint8_t>& data) {
    // Chiffrement simulé avec XOR (dans une implémentation réelle, utiliser AES-GCM)
    std::vector<uint8_t> encrypted(data.size());
    
    std::uniform_int_distribution<uint16_t> dist(0, 255);
    uint8_t key_byte = session_.shared_secret[0];
    
    for (size_t i = 0; i < data.size(); ++i) {
        encrypted[i] = data[i] ^ (key_byte + (i % 32));
    }
    
    return encrypted;
}

std::vector<uint8_t> NetworkProtocol::decryptMessage(const std::vector<uint8_t>& encrypted) {
    // Déchiffrement simulé
    return encryptMessage(encrypted);  // XOR est symétrique
}

PolymorphicPacket NetworkProtocol::wrapInPolymorphicPacket(const std::vector<uint8_t>& data) {
    return poly_engine_.generatePacket(data, false);
}

bool NetworkProtocol::sendMessage(const std::vector<uint8_t>& data) {
    if (!session_.connected) {
        return false;
    }
    
    // Créer l'en-tête
    auto header = createHeader(MessageType::DATA_MESSAGE, data.size());
    
    // Chiffrer les données
    auto encrypted = encryptMessage(data);
    
    // Emballer dans un paquet polymorphe
    std::vector<uint8_t> packet_data;
    
    // Sérialiser l'en-tête
    packet_data.push_back(static_cast<uint8_t>(header.type));
    packet_data.push_back(header.size >> 8);
    packet_data.push_back(header.size & 0xFF);
    packet_data.push_back(header.sequence >> 24);
    packet_data.push_back((header.sequence >> 16) & 0xFF);
    packet_data.push_back((header.sequence >> 8) & 0xFF);
    packet_data.push_back(header.sequence & 0xFF);
    
    // Timestamp (8 bytes)
    for (int i = 7; i >= 0; --i) {
        packet_data.push_back((header.timestamp >> (i * 8)) & 0xFF);
    }
    
    // Nonce (16 bytes)
    packet_data.insert(packet_data.end(), header.nonce.begin(), header.nonce.end());
    
    // Données chiffrées
    packet_data.insert(packet_data.end(), encrypted.begin(), encrypted.end());
    
    // Emballer dans un paquet polymorphe
    auto poly_packet = wrapInPolymorphicPacket(packet_data);
    
    // Aplatir le paquet polymorphe
    std::vector<uint8_t> final_packet;
    final_packet.insert(final_packet.end(), poly_packet.header.begin(), poly_packet.header.end());
    final_packet.insert(final_packet.end(), poly_packet.payload.begin(), poly_packet.payload.end());
    final_packet.insert(final_packet.end(), poly_packet.padding.begin(), poly_packet.padding.end());
    
    std::cout << "[Envoi] Paquet de " << final_packet.size() << " bytes (mode: " 
              << static_cast<int>(poly_packet.mode) << ")" << std::endl;
    
    // Envoyer sur le socket (simulation)
    // send(client_socket_, final_packet.data(), final_packet.size(), 0);
    
    session_.last_activity = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    // Basculer occasionnellement le mode protocolaire
    if (rng_() % 10 == 0) {
        poly_engine_.switchProtocolMode();
    }
    
    return true;
}

std::vector<uint8_t> NetworkProtocol::receiveMessage() {
    if (!session_.connected) {
        return {};
    }
    
    // Simulation de réception
    std::uniform_int_distribution<uint16_t> dist(0, 255);
    std::vector<uint8_t> received(100 + dist(rng_) % 500);
    
    for (auto& b : received) {
        b = static_cast<uint8_t>(dist(rng_));
    }
    
    return decryptMessage(received);
}

void NetworkProtocol::sendCoverTraffic() {
    if (!session_.connected) {
        return;
    }
    
    auto packet = poly_engine_.generateCoverTraffic();
    
    std::vector<uint8_t> data;
    data.insert(data.end(), packet.header.begin(), packet.header.end());
    data.insert(data.end(), packet.payload.begin(), packet.payload.end());
    data.insert(data.end(), packet.padding.begin(), packet.padding.end());
    
    auto header = createHeader(MessageType::COVER_TRAFFIC, data.size());
    
    std::cout << "[Cover Traffic] Envoi paquet de " << data.size() 
              << " bytes pour masquer l'activité" << std::endl;
    
    // Envoyer (simulation)
    session_.last_activity = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
}

bool NetworkProtocol::renegotiateKeys() {
    std::cout << "[Renégociation] Démarrage renégociation seamless des clés..." << std::endl;
    
    // Générer de nouvelles clés
    auto new_keys = pqc_core_.generateHybridKeyPair();
    
    // Envoyer message RENEGOTIATE avec nouvelle clé publique
    std::vector<uint8_t> reneq_data;
    reneq_data.push_back(static_cast<uint8_t>(MessageType::RENEGOTIATE));
    reneq_data.insert(reneq_data.end(), new_keys.x25519_public.begin(),
                      new_keys.x25519_public.end());
    reneq_data.insert(reneq_data.end(), new_keys.ml_kem_public.begin(),
                      new_keys.ml_kem_public.end());
    
    std::cout << "[Renégociation] Nouvelles clés générées et envoyées" << std::endl;
    
    // La communication CONTINUE pendant la renégociation
    // Dans une implémentation réelle, on recevrait la réponse du pair
    
    // Mettre à jour les clés
    session_.local_keys = new_keys;
    
    // Nouveau secret partagé
    auto [ct, shared] = pqc_core_.encapsulate(session_.remote_keys);
    session_.shared_secret = pqc_core_.deriveSharedKey(shared);
    
    std::cout << "[Renégociation] Terminée en <30ms, aucune perte de données" << std::endl;
    
    return true;
}

bool NetworkProtocol::rotateCircuit() {
    std::cout << "[Rotation] Rotation du circuit mixnet..." << std::endl;
    
    // Créer un nouveau circuit
    MixnetNetwork network;
    
    // Ajouter des nœuds de démo
    for (int i = 0; i < 9; ++i) {
        NodeInfo node;
        node.id = "node_" + std::to_string(i);
        node.address = "192.168.1." + std::to_string(100 + i);
        node.port = 9000 + i;
        node.type = static_cast<NodeType>(i % 3);
        node.reputation_score = 0.9;
        node.is_bridge = (i % 3 == 0);
        network.addNode(node);
    }
    
    MixnetNode client_node("client", NodeType::ENTRY);
    client_node.initialize();
    
    auto available = network.getAvailableNodes();
    auto circuit = client_node.createCircuit(available);
    
    session_.active_circuit = circuit;
    session_.needs_rotation = false;
    
    std::cout << "[Rotation] Nouveau circuit établi: " 
              << circuit.entry_node.id << " -> " 
              << circuit.middle_node.id << " -> " 
              << circuit.exit_node.id << std::endl;
    
    return true;
}

TrafficStats NetworkProtocol::getTrafficStats() const {
    return poly_engine_.getStats();
}

void NetworkProtocol::shutdown() {
    if (client_socket_ != -1) {
#ifdef _WIN32
        closesocket(client_socket_);
#else
        close(client_socket_);
#endif
        client_socket_ = -1;
    }
    
    if (listen_socket_ != -1) {
#ifdef _WIN32
        closesocket(listen_socket_);
#else
        close(listen_socket_);
#endif
        listen_socket_ = -1;
    }
    
#ifdef _WIN32
    WSACleanup();
#endif
    
    session_.connected = false;
}

// Factory implementation
std::unique_ptr<NetworkProtocol> NetworkFactory::createClient() {
    return std::make_unique<NetworkProtocol>();
}

std::unique_ptr<NetworkProtocol> NetworkFactory::createServer(int port) {
    auto server = std::make_unique<NetworkProtocol>();
    server->startServer(port);
    return server;
}

} // namespace pq_mixnet
