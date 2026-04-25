#include "protocol.h"
#include <cstring>
#include <algorithm>

namespace pqmix {

// ============================================================================
// ProtocolHeader Implementation
// ============================================================================

std::vector<uint8_t> ProtocolHeader::serialize() const {
    std::vector<uint8_t> data;
    
    // Magic bytes (4)
    data.insert(data.end(), magic, magic + 4);
    
    // Version (1)
    data.push_back(version);
    
    // Type (1)
    data.push_back(static_cast<uint8_t>(type));
    
    // Payload size (2, little-endian)
    data.push_back(payload_size & 0xFF);
    data.push_back((payload_size >> 8) & 0xFF);
    
    // Sequence number (4)
    for (int i = 0; i < 4; ++i) {
        data.push_back((sequence_number >> (i * 8)) & 0xFF);
    }
    
    // Flags (1)
    data.push_back(flags);
    
    return data;
}

std::optional<ProtocolHeader> ProtocolHeader::deserialize(const std::vector<uint8_t>& data) {
    if (data.size() < 13) {
        return std::nullopt;
    }
    
    ProtocolHeader header;
    size_t offset = 0;
    
    // Magic bytes
    for (int i = 0; i < 4 && offset < data.size(); ++i, ++offset) {
        header.magic[i] = data[offset];
    }
    
    // Vérifier magic bytes
    if (header.magic[0] != 'P' || header.magic[1] != 'Q' || 
        header.magic[2] != 'M' || header.magic[3] != 'X') {
        return std::nullopt;
    }
    
    // Version
    if (offset < data.size()) header.version = data[offset++];
    
    // Type
    if (offset < data.size()) header.type = static_cast<MessageType>(data[offset++]);
    
    // Payload size
    if (offset + 2 <= data.size()) {
        header.payload_size = data[offset] | (data[offset + 1] << 8);
        offset += 2;
    }
    
    // Sequence number
    if (offset + 4 <= data.size()) {
        header.sequence_number = 0;
        for (int i = 0; i < 4; ++i) {
            header.sequence_number |= static_cast<uint32_t>(data[offset + i]) << (i * 8);
        }
        offset += 4;
    }
    
    // Flags
    if (offset < data.size()) header.flags = data[offset];
    
    return header;
}

// ============================================================================
// Serialization Utilities
// ============================================================================

std::vector<uint8_t> Serialization::concat(const std::vector<std::vector<uint8_t>>& buffers) {
    size_t total_size = 0;
    for (const auto& buf : buffers) {
        total_size += buf.size();
    }
    
    std::vector<uint8_t> result;
    result.reserve(total_size);
    
    for (const auto& buf : buffers) {
        result.insert(result.end(), buf.begin(), buf.end());
    }
    
    return result;
}

// ============================================================================
// ClientSession Implementation
// ============================================================================

ClientSession::ClientSession(std::mt19937_64& rng)
    : rng_(rng)
    , state_(State::DISCONNECTED)
    , mixnet_(std::make_unique<MixnetNetwork>(rng))
    , poly_engine_(std::make_unique<PolymorphicEngine>(rng))
    , last_key_rotation_(std::chrono::steady_clock::now())
    , last_circuit_rotation_(std::chrono::steady_clock::now())
    , last_packet_sent_(std::chrono::steady_clock::now()) {
}

ClientSession::~ClientSession() = default;

std::vector<uint8_t> ClientSession::initiate_connection(const std::string& server_address) {
    setState(State::CONNECTING);
    server_address_ = server_address;
    
    // Initialiser le handshake PQC hybride
    auto [client_hs, session_keys] = HybridPQSuite::client_init(rng_);
    client_handshake_ = client_hs;
    session_keys_ = session_keys;
    
    setState(State::HANDSHAKE_PQC);
    
    // Construire le message CLIENT_HELLO avec OID Kyber
    ProtocolHeader header;
    header.type = MessageType::CLIENT_HELLO;
    header.set_pqc_oid(true);  // OID Kyber 0x6399 présent
    
    std::vector<uint8_t> payload = client_hs.serialize();
    header.payload_size = static_cast<uint16_t>(payload.size());
    header.sequence_number = sequence_number_++;
    
    std::vector<uint8_t> message = header.serialize();
    message.insert(message.end(), payload.begin(), payload.end());
    
    // Ajouter du padding polymorphique pour atteindre > 2000 bytes
    message = poly_engine_->add_hop_padding(message, 500, 1500);
    
    last_packet_sent_ = std::chrono::steady_clock::now();
    return message;
}

std::vector<uint8_t> ClientSession::complete_handshake(const std::vector<uint8_t>& server_data) {
    // Parser la réponse du serveur
    auto header_opt = ProtocolHeader::deserialize(server_data);
    if (!header_opt || header_opt->type != MessageType::SERVER_HELLO) {
        setState(State::ERROR);
        return {};
    }
    
    // Extraire le ServerHandshake
    size_t payload_start = header_opt->serialize().size();
    std::vector<uint8_t> hs_data(server_data.begin() + payload_start, server_data.end());
    server_handshake_ = HybridPQSuite::ServerHandshake::deserialize(hs_data);
    
    // Compléter l'échange de clés
    session_keys_ = HybridPQSuite::server_complete(client_handshake_, server_handshake_, rng_);
    
    setState(State::AUTHENTICATING);
    
    // Envoyer AUTH_REQUEST
    ProtocolHeader auth_header;
    auth_header.type = MessageType::AUTH_REQUEST;
    auth_header.set_pqc_oid(true);
    auth_header.sequence_number = sequence_number_++;
    
    // Simulation: username + hash de mot de passe
    std::vector<uint8_t> auth_payload = {'u', 's', 'e', 'r', 0};  // "user\0"
    auth_header.payload_size = static_cast<uint16_t>(auth_payload.size());
    
    std::vector<uint8_t> auth_msg = auth_header.serialize();
    auth_msg.insert(auth_msg.end(), auth_payload.begin(), auth_payload.end());
    auth_msg = encrypt_payload(auth_msg);
    auth_msg = poly_engine_->generate_packet(auth_msg);
    
    setState(State::ACTIVE);
    last_key_rotation_ = std::chrono::steady_clock::now();
    
    return auth_msg;
}

std::vector<uint8_t> ClientSession::send_message(const std::vector<uint8_t>& message) {
    if (state_ != State::ACTIVE) {
        return {};
    }
    
    check_key_rotation();
    check_circuit_rotation();
    
    // Chiffrer le message
    std::vector<uint8_t> encrypted = encrypt_payload(message);
    
    // Encapsuler dans le Mixnet (onion routing)
    auto circuit_opt = mixnet_->select_circuit(3, false);
    if (!circuit_opt) {
        return {};
    }
    
    std::vector<uint8_t> onion = mixnet_->build_onion(encrypted, *circuit_opt);
    
    // Appliquer le polymorphisme
    ProtocolHeader header;
    header.type = MessageType::DATA_MESSAGE;
    header.set_pqc_oid(true);
    header.flags |= 0x02;  // Polymorphic padding active
    header.sequence_number = sequence_number_++;
    header.payload_size = static_cast<uint16_t>(onion.size());
    
    std::vector<uint8_t> packet = header.serialize();
    packet.insert(packet.end(), onion.begin(), onion.end());
    packet = poly_engine_->generate_packet(packet);
    
    last_packet_sent_ = std::chrono::steady_clock::now();
    return packet;
}

std::optional<std::vector<uint8_t>> ClientSession::receive_message(const std::vector<uint8_t>& encrypted_data) {
    if (state_ != State::ACTIVE) {
        return std::nullopt;
    }
    
    // Déchiffrer
    std::vector<uint8_t> decrypted = decrypt_payload(encrypted_data);
    
    if (decrypted.empty()) {
        return std::nullopt;
    }
    
    return decrypted;
}

std::vector<uint8_t> ClientSession::generate_idle_traffic() {
    // Générer du trafic de couverture pour éviter les silences > 1s
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_packet_sent_).count();
    
    if (elapsed < 500) {
        return {};  // Pas encore nécessaire
    }
    
    ProtocolHeader header;
    header.type = MessageType::COVER_TRAFFIC;
    header.set_pqc_oid(true);
    header.sequence_number = sequence_number_++;
    
    // Payload aléatoire
    std::uniform_int_distribution<uint16_t> dist(0, 255);
    std::vector<uint8_t> payload(64 + (dist(rng_) % 256));
    for (auto& byte : payload) {
        byte = static_cast<uint8_t>(dist(rng_));
    }
    
    header.payload_size = static_cast<uint16_t>(payload.size());
    
    std::vector<uint8_t> packet = header.serialize();
    packet.insert(packet.end(), payload.begin(), payload.end());
    packet = poly_engine_->generate_packet(packet);
    
    return packet;
}

std::vector<uint8_t> ClientSession::request_renegotiation() {
    ProtocolHeader header;
    header.type = MessageType::RENEGOTIATE;
    header.set_pqc_oid(true);
    header.sequence_number = sequence_number_++;
    
    // Nouvelle clé publique éphémère
    auto [new_priv, new_pub] = X25519::generate_keypair(rng_);
    std::vector<uint8_t> payload(new_pub.begin(), new_pub.end());
    header.payload_size = static_cast<uint16_t>(payload.size());
    
    std::vector<uint8_t> msg = header.serialize();
    msg.insert(msg.end(), payload.begin(), payload.end());
    msg = encrypt_payload(msg);
    
    setState(State::RENEGOTIATING);
    return msg;
}

std::vector<uint8_t> ClientSession::switch_protocol_mode(ProtocolMode new_mode) {
    ProtocolHeader header;
    header.type = MessageType::MODE_SWITCH;
    header.set_pqc_oid(true);
    header.sequence_number = sequence_number_++;
    
    std::vector<uint8_t> payload = {static_cast<uint8_t>(new_mode)};
    header.payload_size = static_cast<uint16_t>(payload.size());
    
    std::vector<uint8_t> msg = header.serialize();
    msg.insert(msg.end(), payload.begin(), payload.end());
    msg = encrypt_payload(msg);
    
    poly_engine_->switch_mode(new_mode);
    return msg;
}

std::vector<uint8_t> ClientSession::rotate_circuit() {
    ProtocolHeader header;
    header.type = MessageType::CIRCUIT_ROTATE;
    header.set_pqc_oid(true);
    header.flags |= 0x08;  // Circuit rotation requested
    header.sequence_number = sequence_number_++;
    
    auto new_circuit = mixnet_->rotate_circuits();
    
    std::vector<uint8_t> payload;
    for (const auto& node : new_circuit.nodes) {
        payload.push_back(static_cast<uint8_t>(node.id.size()));
        payload.insert(payload.end(), node.id.begin(), node.id.end());
    }
    
    header.payload_size = static_cast<uint16_t>(payload.size());
    
    std::vector<uint8_t> msg = header.serialize();
    msg.insert(msg.end(), payload.begin(), payload.end());
    msg = encrypt_payload(msg);
    
    last_circuit_rotation_ = std::chrono::steady_clock::now();
    return msg;
}

bool ClientSession::is_secure() const {
    return state_ == State::ACTIVE;
}

const TrafficStats& ClientSession::get_traffic_stats() const {
    return poly_engine_->get_stats();
}

void ClientSession::setState(State new_state) {
    State old_state = state_;
    state_ = new_state;
    
    if (on_state_change_) {
        std::string state_str;
        switch (new_state) {
            case State::DISCONNECTED: state_str = "Disconnected"; break;
            case State::CONNECTING: state_str = "Connecting"; break;
            case State::HANDSHAKE_PQC: state_str = "Handshake PQC"; break;
            case State::AUTHENTICATING: state_str = "Authenticating"; break;
            case State::ACTIVE: state_str = "Active"; break;
            case State::RENEGOTIATING: state_str = "Renegotiating"; break;
            case State::ERROR: state_str = "Error"; break;
        }
        on_state_change_(state_str);
    }
}

void ClientSession::check_key_rotation() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(now - last_key_rotation_).count();
    
    // Rotation toutes les 5-10 minutes (aléatoire)
    if (elapsed >= 8) {
        session_keys_ = HybridPQSuite::rotate_keys(session_keys_, rng_);
        last_key_rotation_ = now;
        
        // Notifier la renégociation
        if (on_state_change_) {
            on_state_change_("Keys rotated");
        }
    }
}

void ClientSession::check_circuit_rotation() {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::minutes>(now - last_circuit_rotation_).count();
    
    // Rotation toutes les 20 minutes
    if (elapsed >= 20) {
        rotate_circuit();
    }
}

std::vector<uint8_t> ClientSession::encrypt_payload(const std::vector<uint8_t>& plaintext) {
    return AES256GCM::encrypt(plaintext, session_keys_.encryption_key, session_keys_.nonce);
}

std::vector<uint8_t> ClientSession::decrypt_payload(const std::vector<uint8_t>& ciphertext) {
    return AES256GCM::decrypt(ciphertext, session_keys_.encryption_key, session_keys_.nonce);
}

// ============================================================================
// ServerSession Implementation
// ============================================================================

ServerSession::ServerSession(std::mt19937_64& rng)
    : rng_(rng) {
}

std::vector<uint8_t> ServerSession::initialize_server() {
    // Générer les clés PQC du serveur
    server_handshake_.ml_kem_keys = MLKEM::generate_keypair(rng_);
    server_handshake_.x25519_keys = X25519::generate_keypair(rng_);
    
    // Signer avec ML-DSA (créer une clé ML-DSA dédiée)
    std::vector<uint8_t> server_info = {'S', 'E', 'R', 'V', 'E', 'R'};
    auto ml_dsa_keys = MLDSA::generate_keypair(rng_);
    server_handshake_.signature = MLDSA::sign(server_info, ml_dsa_keys.secret_key, rng_);
    
    return server_handshake_.serialize();
}

std::vector<uint8_t> ServerSession::handle_client_hello(const std::vector<uint8_t>& client_hello,
                                                         const std::string& client_id) {
    stats_.total_connections++;
    
    // Sélectionner aléatoirement une suite cryptographique (0-8)
    uint8_t suite_index = select_crypto_suite();
    
    // Créer le contexte client
    auto context = std::make_unique<ClientContext>();
    context->id = client_id;
    context->connected_at = std::chrono::steady_clock::now();
    context->last_activity = std::chrono::steady_clock::now();
    context->current_mode = ProtocolMode::WEBRTC_QUIC;
    context->sequence_number = 0;
    context->mixnet = std::make_unique<MixnetNetwork>(rng_);
    context->poly_engine = std::make_unique<PolymorphicEngine>(rng_);
    
    // Initialiser le réseau Mixnet avec des nœuds simulés
    for (int i = 0; i < 10; ++i) {
        NodeInfo node;
        node.id = "node_" + std::to_string(i);
        node.address = "192.168.1." + std::to_string(100 + i);
        node.port = 9000 + i;
        node.type = static_cast<NodeType>(i % 4);
        node.reputation_score = 0.8 + (rng_() % 100) / 500.0;
        node.is_active = true;
        node.supports_pqc = true;
        context->mixnet->add_node(node);
    }
    
    clients_[client_id] = std::move(context);
    
    // Construire SERVER_HELLO
    ProtocolHeader header;
    header.type = MessageType::SERVER_HELLO;
    header.set_pqc_oid(true);
    
    std::vector<uint8_t> payload = server_handshake_.serialize();
    header.payload_size = static_cast<uint16_t>(std::min(payload.size(), size_t(65535)));
    
    std::vector<uint8_t> response = header.serialize();
    response.insert(response.end(), payload.begin(), payload.begin() + header.payload_size);
    
    // Ajouter du padding pour > 2000 bytes (preuve PQC)
    std::uniform_int_distribution<size_t> pad_dist(500, 1500);
    std::uniform_int_distribution<uint16_t> byte_dist(0, 255);
    size_t pad_size = pad_dist(rng_);
    for (size_t i = 0; i < pad_size; ++i) {
        response.push_back(static_cast<uint8_t>(byte_dist(rng_)));
    }
    
    return response;
}

std::vector<uint8_t> ServerSession::complete_handshake(const std::vector<uint8_t>& kem_data,
                                                        const std::string& client_id) {
    auto it = clients_.find(client_id);
    if (it == clients_.end()) {
        return {};
    }
    
    auto& context = it->second;
    
    // Parser le ClientHandshake
    HybridPQSuite::ClientHandshake client_hs = HybridPQSuite::ClientHandshake::deserialize(kem_data);
    
    // Compléter l'échange de clés
    context->keys = HybridPQSuite::server_complete(client_hs, server_handshake_, rng_);
    context->is_authenticated = true;
    
    stats_.pqc_handshakes_completed++;
    
    // Réponse de confirmation
    ProtocolHeader header;
    header.type = MessageType::AUTH_RESPONSE;
    header.set_pqc_oid(true);
    header.sequence_number = context->sequence_number++;
    
    std::vector<uint8_t> payload = {0x01};  // Success
    header.payload_size = 1;
    
    std::vector<uint8_t> msg = header.serialize();
    msg.insert(msg.end(), payload.begin(), payload.end());
    
    // Chiffrer avec la clé de session
    msg = AES256GCM::encrypt(msg, context->keys.encryption_key, context->keys.nonce);
    
    return msg;
}

std::optional<std::vector<uint8_t>> ServerSession::handle_message(const std::string& client_id,
                                                                    const std::vector<uint8_t>& encrypted_data) {
    auto it = clients_.find(client_id);
    if (it == clients_.end()) {
        return std::nullopt;
    }
    
    auto& context = it->second;
    context->last_activity = std::chrono::steady_clock::now();
    
    // Déchiffrer
    std::vector<uint8_t> decrypted = AES256GCM::decrypt(encrypted_data, 
                                                         context->keys.encryption_key,
                                                         context->keys.nonce);
    
    if (decrypted.empty()) {
        return std::nullopt;
    }
    
    // Parser le header
    auto header_opt = ProtocolHeader::deserialize(decrypted);
    if (!header_opt) {
        return std::nullopt;
    }
    
    // Gérer selon le type de message
    switch (header_opt->type) {
        case MessageType::RENEGOTIATE:
            // Rotation des clés
            context->keys = HybridPQSuite::rotate_keys(context->keys, rng_);
            break;
            
        case MessageType::MODE_SWITCH:
            // Changement de mode
            if (decrypted.size() > 13) {
                ProtocolMode new_mode = static_cast<ProtocolMode>(decrypted[13]);
                context->current_mode = new_mode;
                context->poly_engine->switch_mode(new_mode);
                stats_.mode_switches++;
                stats_.active_modes[new_mode]++;
            }
            break;
            
        case MessageType::CIRCUIT_ROTATE:
            context->mixnet->rotate_circuits();
            stats_.circuits_rotated++;
            break;
            
        default:
            // Message de données normal
            if (on_client_message_) {
                on_client_message_(client_id, decrypted);
            }
            break;
    }
    
    // Réponse optionnelle
    return std::nullopt;
}

void ServerSession::disconnect_client(const std::string& client_id) {
    if (on_client_disconnect_) {
        on_client_disconnect_(client_id);
    }
    clients_.erase(client_id);
}

void ServerSession::broadcast_to_all(const std::vector<uint8_t>& message) {
    for (auto& [id, context] : clients_) {
        // Chiffrer et envoyer à chaque client
        auto encrypted = AES256GCM::encrypt(message, context->keys.encryption_key, context->keys.nonce);
        if (on_client_message_) {
            on_client_message_(id, encrypted);
        }
    }
}

uint8_t ServerSession::select_crypto_suite() {
    // Sélection aléatoire parmi 9 suites cryptographiques
    std::uniform_int_distribution<int> dist(0, 8);
    return static_cast<uint8_t>(dist(rng_));
}

} // namespace pqmix
