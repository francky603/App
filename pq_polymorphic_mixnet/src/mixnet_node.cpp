#include "mixnet_node.h"
#include <algorithm>
#include <numeric>
#include <cstring>
#include <optional>

namespace pqmix {

// ============================================================================
// VRF Implementation (Verifiable Random Function - Post-Quantique)
// ============================================================================

std::pair<std::vector<uint8_t>, std::vector<uint8_t>> 
VRF::prove(const std::vector<uint8_t>& secret_key, const std::vector<uint8_t>& input) {
    // Simulation d'une VRF post-quantique
    // En production: utiliser une VRF basée sur des réseaux euclidiens (lattice-based)
    
    std::string combined;
    combined.reserve(secret_key.size() + input.size());
    combined.append(secret_key.begin(), secret_key.end());
    combined.append(input.begin(), input.end());
    
    // Hash déterministe
    std::mt19937 vrf(std::hash<std::string>{}(combined));
    std::uniform_int_distribution<uint16_t> dist(0, 255);
    
    // Preuve VRF (64 bytes simulés)
    std::vector<uint8_t> proof(64);
    for (size_t i = 0; i < 64; ++i) {
        proof[i] = static_cast<uint8_t>(dist(vrf));
    }
    
    // Sortie aléatoire (32 bytes)
    std::vector<uint8_t> output(32);
    for (size_t i = 0; i < 32; ++i) {
        output[i] = static_cast<uint8_t>(dist(vrf));
    }
    
    return {proof, output};
}

bool VRF::verify(const std::vector<uint8_t>& public_key,
                 const std::vector<uint8_t>& input,
                 const std::vector<uint8_t>& proof,
                 const std::vector<uint8_t>& expected_output) {
    // Vérification simplifiée de la preuve VRF
    if (proof.size() < 32 || expected_output.size() < 16) {
        return false;
    }
    
    // En prod: vérification cryptographique complète de la VRF
    // Ici: simulation basique
    size_t proof_hash = std::accumulate(proof.begin(), proof.end(), size_t(0),
                                         [](size_t a, uint8_t b) { return (a << 1) ^ b; });
    size_t output_hash = std::accumulate(expected_output.begin(), expected_output.end(), size_t(0),
                                          [](size_t a, uint8_t b) { return (a << 1) ^ b; });
    
    // La preuve est valide si elle a une structure cohérente
    return (proof_hash % 256) > 50;  // 75% de chance de succès simulé
}

// ============================================================================
// MixnetNetwork Implementation
// ============================================================================

MixnetNetwork::MixnetNetwork(std::mt19937_64& rng)
    : rng_(rng)
    , last_rotation_(std::chrono::steady_clock::now()) {
}

void MixnetNetwork::add_node(const NodeInfo& node) {
    nodes_[node.id] = node;
}

void MixnetNetwork::remove_node(const std::string& node_id) {
    nodes_.erase(node_id);
}

NodeInfo MixnetNetwork::select_node_by_type(NodeType type, const std::set<std::string>& exclude) {
    std::vector<NodeInfo> candidates;
    
    for (const auto& [id, node] : nodes_) {
        if (node.type == type && node.is_active && exclude.find(id) == exclude.end()) {
            candidates.push_back(node);
        }
    }
    
    if (candidates.empty()) {
        // Fallback: n'importe quel nœud actif
        for (const auto& [id, node] : nodes_) {
            if (node.is_active && exclude.find(id) == exclude.end()) {
                return node;
            }
        }
        // Dernier recours: retourner un nœud par défaut
        NodeInfo default_node;
        default_node.id = "default";
        default_node.type = type;
        return default_node;
    }
    
    // Sélection aléatoire pondérée par la réputation
    std::uniform_real_distribution<double> dist(0.0, 1.0);
    double total_rep = 0.0;
    for (const auto& node : candidates) {
        total_rep += node.reputation_score;
    }
    
    double target = dist(rng_) * total_rep;
    double cumulative = 0.0;
    
    for (const auto& node : candidates) {
        cumulative += node.reputation_score;
        if (cumulative >= target) {
            return node;
        }
    }
    
    return candidates.back();
}

std::vector<uint8_t> MixnetNetwork::generate_vrf_seed() {
    std::uniform_int_distribution<uint16_t> dist(0, 255);
    std::vector<uint8_t> seed(32);
    
    // Seed basé sur timestamp + randomness
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::seconds>(
        now.time_since_epoch()).count();
    
    for (int i = 0; i < 8; ++i) {
        seed[i] = static_cast<uint8_t>((timestamp >> (i * 8)) & 0xFF);
    }
    for (size_t i = 8; i < 32; ++i) {
        seed[i] = static_cast<uint8_t>(dist(rng_));
    }
    
    return seed;
}

std::optional<MixnetCircuit> MixnetNetwork::select_circuit(size_t required_hops, bool include_bridge) {
    MixnetCircuit circuit;
    circuit.created_at = std::chrono::steady_clock::now();
    circuit.total_delay = std::chrono::milliseconds(0);
    
    std::set<std::string> excluded_nodes;
    std::vector<NodeType> node_types;
    
    // Construction de la liste des types de nœuds requis
    if (include_bridge) {
        node_types.push_back(NodeType::BRIDGE);
        required_hops = std::max(required_hops, size_t(4));  // Bridge + 3 minimum
    }
    
    // Toujours commencer par ENTRY
    node_types.push_back(NodeType::ENTRY);
    
    // Ajouter les nœuds MIDDLE
    for (size_t i = 0; i < required_hops - 2; ++i) {
        node_types.push_back(NodeType::MIDDLE);
    }
    
    // Terminer par EXIT
    node_types.push_back(NodeType::EXIT);
    
    // Sélectionner chaque nœud via VRF
    auto vrf_seed = generate_vrf_seed();
    
    for (NodeType type : node_types) {
        // Utiliser VRF pour sélection vérifiable
        std::vector<uint8_t> node_secret(32, 0);  // Secret du répertoire (simulé)
        auto [vrf_proof, vrf_output] = VRF::prove(node_secret, vrf_seed);
        
        // Incorporer le output VRF dans le seed pour ce saut
        vrf_seed.insert(vrf_seed.end(), vrf_output.begin(), vrf_output.end());
        
        // Sélectionner le nœud
        NodeInfo selected = select_node_by_type(type, excluded_nodes);
        excluded_nodes.insert(selected.id);
        
        circuit.nodes.push_back(selected);
        
        // Générer un secret partagé pour ce saut (32 bytes)
        std::array<uint8_t, 32> shared_secret;
        std::uniform_int_distribution<uint16_t> dist(0, 255);
        for (auto& byte : shared_secret) {
            byte = static_cast<uint8_t>(dist(rng_));
        }
        circuit.shared_secrets.push_back(shared_secret);
        
        // Calculer le délai aléatoire pour ce nœud (10-1000ms)
        std::uniform_int_distribution<uint32_t> delay_dist(10, 1000);
        circuit.total_delay += std::chrono::milliseconds(delay_dist(rng_));
    }
    
    active_circuits_.push_back(circuit);
    return circuit;
}

std::vector<uint8_t> MixnetNetwork::build_onion(const std::vector<uint8_t>& payload,
                                                  const MixnetCircuit& circuit) {
    // Construction de l'oignon (onion routing)
    // Chaque couche est chiffrée avec la clé du nœud correspondant
    
    std::vector<uint8_t> current_layer = payload;
    
    // Créer l'en-tête Mixnet polymorphique
    MixnetHeader header = MixnetHeader::create_polymorphic(rng_, circuit.hop_count());
    std::vector<uint8_t> header_data = header.serialize();
    
    // Empiler les couches de l'oignon (de EXIT vers ENTRY)
    for (int hop = static_cast<int>(circuit.nodes.size()) - 1; hop >= 0; --hop) {
        // Ajouter les instructions pour ce nœud
        std::vector<uint8_t> layer_content;
        
        if (hop == static_cast<int>(circuit.nodes.size()) - 1) {
            // Dernière couche: message final + header
            layer_content.insert(layer_content.end(), header_data.begin(), header_data.end());
            layer_content.insert(layer_content.end(), current_layer.begin(), current_layer.end());
        } else {
            // Couches intermédiaires: instructions de routage + couche suivante
            layer_content.insert(layer_content.end(), header_data.begin(), header_data.end());
            layer_content.insert(layer_content.end(), current_layer.begin(), current_layer.end());
        }
        
        // Chiffrer cette couche avec la clé du nœud (simulation AES)
        const auto& secret = circuit.shared_secrets[hop];
        std::mt19937 prf(std::hash<std::string>{}(
            std::string(secret.begin(), secret.end())));
        std::uniform_int_distribution<uint16_t> dist(0, 255);
        
        current_layer.clear();
        for (size_t i = 0; i < layer_content.size(); ++i) {
            uint8_t keystream = static_cast<uint8_t>(dist(prf));
            current_layer.push_back(layer_content[i] ^ keystream);
        }
        
        // Ajouter du padding aléatoire pour cette couche
        std::uniform_int_distribution<size_t> pad_dist(64, 256);
        size_t pad_size = pad_dist(rng_);
        for (size_t i = 0; i < pad_size; ++i) {
            current_layer.push_back(static_cast<uint8_t>(dist(rng_)));
        }
    }
    
    return current_layer;
}

std::vector<uint8_t> MixnetNetwork::unwrap_layer(const std::vector<uint8_t>& onion_packet,
                                                   const std::vector<uint8_t>& node_secret) {
    // Déchiffrer une couche de l'oignon (côté nœud)
    std::mt19937 prf(std::hash<std::string>{}(
        std::string(node_secret.begin(), node_secret.end())));
    std::uniform_int_distribution<uint16_t> dist(0, 255);
    
    std::vector<uint8_t> decrypted;
    for (size_t i = 0; i < onion_packet.size(); ++i) {
        uint8_t keystream = static_cast<uint8_t>(dist(prf));
        decrypted.push_back(onion_packet[i] ^ keystream);
    }
    
    // Parser l'en-tête pour déterminer la prochaine destination
    MixnetHeader header = MixnetHeader::deserialize(decrypted);
    
    // Retourner le paquet intérieur (sans le header de cette couche)
    size_t header_size = 10 + 4 + header.ephemeral_key.size() + 4 + header.padding.size();
    if (header_size >= decrypted.size()) {
        return {};  // Erreur
    }
    
    return std::vector<uint8_t>(decrypted.begin() + header_size, decrypted.end());
}

void MixnetNetwork::apply_random_delay(uint32_t min_ms, uint32_t max_ms) {
    std::uniform_int_distribution<uint32_t> delay_dist(min_ms, max_ms);
    uint32_t delay = delay_dist(rng_);
    
    // Simulation du délai (en prod: std::this_thread::sleep_for)
    // Le délai casse l'analyse temporelle du trafic
}

MixnetCircuit MixnetNetwork::rotate_circuits() {
    // Force la rotation après 20 minutes
    auto new_circuit_opt = select_circuit(3, false);
    
    if (!new_circuit_opt.has_value()) {
        // Créer un circuit minimal en cas d'échec
        MixnetCircuit fallback;
        fallback.created_at = std::chrono::steady_clock::now();
        return fallback;
    }
    
    last_rotation_ = std::chrono::steady_clock::now();
    stats_.circuits_rotated++;
    
    return *new_circuit_opt;
}

std::map<NodeType, size_t> MixnetNetwork::get_node_counts() const {
    std::map<NodeType, size_t> counts;
    counts[NodeType::ENTRY] = 0;
    counts[NodeType::MIDDLE] = 0;
    counts[NodeType::EXIT] = 0;
    counts[NodeType::BRIDGE] = 0;
    
    for (const auto& [id, node] : nodes_) {
        if (node.is_active) {
            counts[node.type]++;
        }
    }
    
    return counts;
}

bool MixnetNetwork::detect_censorship(const std::string& node_address) {
    // Détection de censure par analyse des réponses
    // Les ponts polymorphes ne répondent à aucun protocole connu
    
    censorship_attempts_detected_++;
    
    // Simulation: 10% de détection de censure
    std::uniform_int_distribution<int> dist(0, 100);
    bool censored = dist(rng_) < 10;
    
    if (!censored) {
        successful_bridge_connections_++;
    }
    
    return censored;
}

// ============================================================================
// MixNode Implementation
// ============================================================================

MixNode::MixNode(const NodeInfo& info, std::mt19937_64& rng)
    : info_(info)
    , rng_(rng) {
    
    // Initialiser la clé secrète pour déchiffrer la couche
    std::uniform_int_distribution<uint16_t> dist(0, 255);
    secret_key_.resize(32);
    for (auto& byte : secret_key_) {
        byte = static_cast<uint8_t>(dist(rng));
    }
}

std::optional<std::vector<uint8_t>> MixNode::process_packet(const std::vector<uint8_t>& incoming_packet) {
    stats_.packets_processed++;
    
    // Déchiffrer la couche externe
    std::vector<uint8_t> unwrapped;
    
    // Simulation du déchiffrement
    std::mt19937 prf(std::hash<std::string>{}(
        std::string(secret_key_.begin(), secret_key_.end())));
    std::uniform_int_distribution<uint16_t> dist(0, 255);
    
    for (size_t i = 0; i < incoming_packet.size(); ++i) {
        uint8_t keystream = static_cast<uint8_t>(dist(prf));
        unwrapped.push_back(incoming_packet[i] ^ keystream);
    }
    
    // Parser l'en-tête
    MixnetHeader header = MixnetHeader::deserialize(unwrapped);
    
    // Appliquer un délai aléatoire (simulation)
    // En prod: std::this_thread::sleep_for(std::chrono::milliseconds(delay))
    (void)header.delay_ms;  // Supprime warning unused
    
    // Si dernier saut, retourner le message final
    if (header.hop_count <= 1) {
        // Message arrivé à destination
        size_t header_size = 10 + 4 + header.ephemeral_key.size() + 4 + header.padding.size();
        if (header_size >= unwrapped.size()) {
            stats_.packets_dropped++;
            return std::nullopt;
        }
        return std::vector<uint8_t>(unwrapped.begin() + header_size, unwrapped.end());
    }
    
    // Sinon, retourner le paquet pour le prochain saut
    size_t header_size = 10 + 4 + header.ephemeral_key.size() + 4 + header.padding.size();
    if (header_size >= unwrapped.size()) {
        stats_.packets_dropped++;
        return std::nullopt;
    }
    
    return std::vector<uint8_t>(unwrapped.begin() + header_size, unwrapped.end());
}

void MixNode::queue_for_transmission(const std::vector<uint8_t>& packet,
                                      std::chrono::milliseconds delay) {
    // Mise en file d'attente avec délai (simulation)
    stats_.avg_delay = (stats_.avg_delay + delay) / 2;
    if (delay > stats_.max_delay) {
        stats_.max_delay = delay;
    }
}

} // namespace pqmix
