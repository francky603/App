#include "mixnet_node.h"
#include <sstream>
#include <iomanip>
#include <algorithm>

namespace pq_mixnet {

// VRF Selector implementation
VrfSelector::VrfSelector(const std::array<uint8_t, 32>& seed) 
    : seed_(seed), pqc_() {}

NodeInfo VrfSelector::selectNode(const std::vector<NodeInfo>& nodes, const std::string& role) {
    if (nodes.empty()) {
        throw std::runtime_error("Aucun nœud disponible pour sélection");
    }
    
    // Utiliser le seed PQC pour générer un hash vérifiable
    auto hash = pqc_.sha3_256(seed_.data(), seed_.size());
    
    // Incorporer le rôle dans la sélection
    std::vector<uint8_t> input(seed_.begin(), seed_.end());
    input.insert(input.end(), role.begin(), role.end());
    hash = pqc_.sha3_256(input.data(), input.size());
    
    // Sélectionner un index basé sur le hash
    uint64_t index_val = 0;
    for (size_t i = 0; i < 8 && i < hash.size(); ++i) {
        index_val |= (static_cast<uint64_t>(hash[i]) << (i * 8));
    }
    size_t index = index_val % nodes.size();
    
    return nodes[index];
}

bool VrfSelector::verifySelection(const NodeInfo& node, const std::vector<uint8_t>& proof) {
    // Vérification simplifiée (dans une implémentation réelle, vérifier la preuve VRF)
    return !proof.empty() && !node.id.empty();
}

// MixnetNode implementation
MixnetNode::MixnetNode(const std::string& node_id, NodeType type) 
    : pqc_core_()
    , poly_engine_()
    , rng_(std::random_device{}()) {
    
    info_.id = node_id;
    info_.type = type;
    info_.port = 9000;
    info_.reputation_score = 1.0;
    info_.last_seen = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    info_.is_bridge = false;
    
    // Initialiser la clé publique ML-DSA
    std::uniform_int_distribution<uint16_t> dist(0, 255);
    for (size_t i = 0; i < ML_DSA_PUBLIC_KEY_SIZE; ++i) {
        info_.public_key[i] = static_cast<uint8_t>(dist(rng_));
    }
}

void MixnetNode::initialize() {
    // Générer un seed pour VRF
    std::array<uint8_t, 32> seed;
    std::uniform_int_distribution<uint16_t> dist(0, 255);
    for (size_t i = 0; i < 32; ++i) {
        seed[i] = static_cast<uint8_t>(dist(rng_));
    }
    
    vrf_selector_ = std::make_unique<VrfSelector>(seed);
}

MixCircuit MixnetNode::createCircuit(const std::vector<NodeInfo>& available_nodes) {
    if (available_nodes.size() < 3) {
        throw std::runtime_error("Au moins 3 nœuds requis pour un circuit mixnet");
    }
    
    // Séparer les nœuds par type
    std::vector<NodeInfo> entry_nodes, middle_nodes, exit_nodes;
    
    for (const auto& node : available_nodes) {
        switch (node.type) {
            case NodeType::ENTRY:
                entry_nodes.push_back(node);
                break;
            case NodeType::MIDDLE:
                middle_nodes.push_back(node);
                break;
            case NodeType::EXIT:
                exit_nodes.push_back(node);
                break;
        }
    }
    
    // Si pas de classification, utiliser tous les nœuds pour chaque rôle
    if (entry_nodes.empty()) entry_nodes = available_nodes;
    if (middle_nodes.empty()) middle_nodes = available_nodes;
    if (exit_nodes.empty()) exit_nodes = available_nodes;
    
    // Sélectionner les nœuds avec VRF
    std::uniform_int_distribution<uint16_t> dist(0, 255);
    std::array<uint8_t, 32> seed;
    for (size_t i = 0; i < 32; ++i) {
        seed[i] = static_cast<uint8_t>(dist(rng_));
    }
    
    VrfSelector selector(seed);
    
    MixCircuit circuit;
    circuit.entry_node = selector.selectNode(entry_nodes, "entry");
    circuit.middle_node = selector.selectNode(middle_nodes, "middle");
    circuit.exit_node = selector.selectNode(exit_nodes, "exit");
    
    // Générer une clé de session
    auto keys = pqc_core_.generateHybridKeyPair();
    auto [ct, shared] = pqc_core_.encapsulate(keys);
    circuit.session_key = pqc_core_.deriveSharedKey(shared);
    
    circuit.creation_time = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    circuit.rotation_time = circuit.creation_time + 1200;  // 20 minutes
    circuit.is_active = true;
    
    return circuit;
}

std::vector<OnionLayer> MixnetNode::buildOnionLayers(const std::vector<uint8_t>& data,
                                                      const MixCircuit& circuit) {
    std::vector<OnionLayer> layers;
    
    // Couche de sortie (la plus interne)
    OnionLayer exit_layer;
    exit_layer.next_hop = circuit.exit_node.address;
    exit_layer.delay_ms = 10 + (rng_() % 991);  // 10-1000ms
    exit_layer.payload = data;
    
    // En-tête variable
    std::uniform_int_distribution<uint16_t> dist(0, 255);
    size_t header_size = 32 + (dist(rng_) % 128);
    exit_layer.header.resize(header_size);
    for (size_t i = 0; i < header_size; ++i) {
        exit_layer.header[i] = static_cast<uint8_t>(dist(rng_));
    }
    
    // Padding aléatoire
    size_t pad_size = 64 + (dist(rng_) % 256);
    exit_layer.padding.resize(pad_size);
    for (size_t i = 0; i < pad_size; ++i) {
        exit_layer.padding[i] = static_cast<uint8_t>(dist(rng_));
    }
    
    layers.push_back(exit_layer);
    
    // Couche intermédiaire
    OnionLayer middle_layer;
    middle_layer.next_hop = circuit.middle_node.address;
    middle_layer.delay_ms = 10 + (rng_() % 991);
    
    // Encoder la couche précédente dans le payload
    for (const auto& b : layers[0].header) middle_layer.payload.push_back(b);
    for (const auto& b : layers[0].payload) middle_layer.payload.push_back(b);
    for (const auto& b : layers[0].padding) middle_layer.payload.push_back(b);
    
    header_size = 32 + (dist(rng_) % 128);
    middle_layer.header.resize(header_size);
    for (size_t i = 0; i < header_size; ++i) {
        middle_layer.header[i] = static_cast<uint8_t>(dist(rng_));
    }
    
    pad_size = 64 + (dist(rng_) % 256);
    middle_layer.padding.resize(pad_size);
    for (size_t i = 0; i < pad_size; ++i) {
        middle_layer.padding[i] = static_cast<uint8_t>(dist(rng_));
    }
    
    layers.insert(layers.begin(), middle_layer);
    
    // Couche d'entrée (la plus externe)
    OnionLayer entry_layer;
    entry_layer.next_hop = circuit.entry_node.address;
    entry_layer.delay_ms = 10 + (rng_() % 991);
    
    // Encoder la couche précédente dans le payload
    for (const auto& b : layers[1].header) entry_layer.payload.push_back(b);
    for (const auto& b : layers[1].payload) entry_layer.payload.push_back(b);
    for (const auto& b : layers[1].padding) entry_layer.payload.push_back(b);
    
    header_size = 32 + (dist(rng_) % 128);
    entry_layer.header.resize(header_size);
    for (size_t i = 0; i < header_size; ++i) {
        entry_layer.header[i] = static_cast<uint8_t>(dist(rng_));
    }
    
    pad_size = 64 + (dist(rng_) % 256);
    entry_layer.padding.resize(pad_size);
    for (size_t i = 0; i < pad_size; ++i) {
        entry_layer.padding[i] = static_cast<uint8_t>(dist(rng_));
    }
    
    layers.insert(layers.begin(), entry_layer);
    
    return layers;
}

std::vector<uint8_t> MixnetNode::buildOnionPacket(const std::vector<uint8_t>& data,
                                                   const MixCircuit& circuit) {
    auto layers = buildOnionLayers(data, circuit);
    
    // Aplatir toutes les couches en un seul paquet
    std::vector<uint8_t> packet;
    
    // Ajouter le nombre de couches
    packet.push_back(static_cast<uint8_t>(layers.size()));
    
    for (const auto& layer : layers) {
        // Encoder: taille header + header + taille payload + payload + taille padding + padding + next_hop
        uint16_t h_size = static_cast<uint16_t>(layer.header.size());
        uint16_t p_size = static_cast<uint16_t>(layer.payload.size());
        uint16_t pad_size = static_cast<uint16_t>(layer.padding.size());
        
        packet.push_back(h_size >> 8);
        packet.push_back(h_size & 0xFF);
        packet.insert(packet.end(), layer.header.begin(), layer.header.end());
        
        packet.push_back(p_size >> 8);
        packet.push_back(p_size & 0xFF);
        packet.insert(packet.end(), layer.payload.begin(), layer.payload.end());
        
        packet.push_back(pad_size >> 8);
        packet.push_back(pad_size & 0xFF);
        packet.insert(packet.end(), layer.padding.begin(), layer.padding.end());
        
        // Next hop (1 byte pour la longueur + données)
        packet.push_back(static_cast<uint8_t>(layer.next_hop.size()));
        packet.insert(packet.end(), layer.next_hop.begin(), layer.next_hop.end());
        
        // Délai
        packet.push_back(layer.delay_ms >> 24);
        packet.push_back((layer.delay_ms >> 16) & 0xFF);
        packet.push_back((layer.delay_ms >> 8) & 0xFF);
        packet.push_back(layer.delay_ms & 0xFF);
    }
    
    return packet;
}

std::pair<std::vector<uint8_t>, std::string> MixnetNode::peelLayer(
    const std::vector<uint8_t>& onion_data) {
    
    if (onion_data.empty()) {
        return {{}, ""};
    }
    
    size_t idx = 0;
    uint8_t num_layers = onion_data[idx++];
    
    if (num_layers == 0 || idx >= onion_data.size()) {
        return {{}, ""};
    }
    
    // Lire la première couche
    if (idx + 2 > onion_data.size()) return {{}, ""};
    uint16_t h_size = (onion_data[idx] << 8) | onion_data[idx + 1];
    idx += 2;
    
    if (idx + h_size > onion_data.size()) return {{}, ""};
    idx += h_size;  // Skip header
    
    if (idx + 2 > onion_data.size()) return {{}, ""};
    uint16_t p_size = (onion_data[idx] << 8) | onion_data[idx + 1];
    idx += 2;
    
    if (idx + p_size > onion_data.size()) return {{}, ""};
    std::vector<uint8_t> payload(onion_data.begin() + idx, onion_data.begin() + idx + p_size);
    idx += p_size;
    
    if (idx + 2 > onion_data.size()) return {{}, ""};
    uint16_t pad_size = (onion_data[idx] << 8) | onion_data[idx + 1];
    idx += 2;
    
    if (idx + pad_size > onion_data.size()) return {{}, ""};
    idx += pad_size;  // Skip padding
    
    if (idx + 1 > onion_data.size()) return {{}, ""};
    uint8_t hop_len = onion_data[idx++];
    
    if (idx + hop_len > onion_data.size()) return {{}, ""};
    std::string next_hop(onion_data.begin() + idx, onion_data.begin() + idx + hop_len);
    idx += hop_len;
    
    // Skip delay (4 bytes)
    idx += 4;
    
    // Retourner le reste (couches internes) et le prochain saut
    std::vector<uint8_t> remaining;
    if (idx < onion_data.size()) {
        // Reconstruire l'oignon avec une couche en moins
        remaining.push_back(num_layers - 1);
        remaining.insert(remaining.end(), onion_data.begin() + idx, onion_data.end());
    }
    
    return {payload, next_hop};
}

void MixnetNode::applyRandomDelay() {
    std::uniform_int_distribution<uint32_t> dist(10, 1000);  // 10-1000ms
    uint32_t delay_ms = dist(rng_);
    
    // Simulation du délai (dans une implémentation réelle, utiliser sleep)
    (void)delay_ms;  // Supprimer warning unused
}

bool MixnetNode::shouldRotateCircuit() const {
    uint64_t now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    // Rotation toutes les 20 minutes (1200 secondes)
    // Avec une variation aléatoire de ±2 minutes
    return now > 1200;  // Simplifié pour démo
}

std::vector<uint8_t> MixnetNode::generateCoverTraffic() {
    auto packet = poly_engine_.generateCoverTraffic();
    
    std::vector<uint8_t> data;
    data.insert(data.end(), packet.header.begin(), packet.header.end());
    data.insert(data.end(), packet.payload.begin(), packet.payload.end());
    data.insert(data.end(), packet.padding.begin(), packet.padding.end());
    
    return data;
}

// MixnetNetwork implementation
MixnetNetwork::MixnetNetwork() : rng_(std::random_device{}()) {}

void MixnetNetwork::addNode(const NodeInfo& node) {
    nodes_.push_back(node);
}

std::vector<NodeInfo> MixnetNetwork::getAvailableNodes() const {
    return nodes_;
}

std::tuple<NodeInfo, NodeInfo, NodeInfo> MixnetNetwork::selectCircuitNodes() {
    if (nodes_.size() < 3) {
        throw std::runtime_error("Au moins 3 nœuds requis");
    }
    
    std::uniform_int_distribution<size_t> dist(0, nodes_.size() - 1);
    
    size_t idx1 = dist(rng_);
    size_t idx2 = dist(rng_);
    while (idx2 == idx1) idx2 = dist(rng_);
    
    size_t idx3 = dist(rng_);
    while (idx3 == idx1 || idx3 == idx2) idx3 = dist(rng_);
    
    return {nodes_[idx1], nodes_[idx2], nodes_[idx3]};
}

void MixnetNetwork::updateReputation(const std::string& node_id, double delta) {
    for (auto& node : nodes_) {
        if (node.id == node_id) {
            node.reputation_score += delta;
            if (node.reputation_score > 1.0) node.reputation_score = 1.0;
            if (node.reputation_score < 0.0) node.reputation_score = 0.0;
            break;
        }
    }
}

} // namespace pq_mixnet
