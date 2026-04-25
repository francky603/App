#ifndef MIXNET_NODE_H
#define MIXNET_NODE_H

#include <vector>
#include <array>
#include <string>
#include <random>
#include <unordered_map>
#include <memory>
#include "pqc_core.h"
#include "polymorphic_engine.h"

namespace pq_mixnet {

// Types de nœuds dans le Mixnet
enum class NodeType {
    ENTRY,    // Nœud d'entrée
    MIDDLE,   // Nœud intermédiaire
    EXIT      // Nœud de sortie
};

// Information sur un nœud
struct NodeInfo {
    std::string id;
    std::string address;
    uint16_t port;
    NodeType type;
    std::array<uint8_t, ML_DSA_PUBLIC_KEY_SIZE> public_key;
    uint64_t last_seen;
    double reputation_score;
    bool is_bridge;  // Pont polymorphe
};

// Couche d'oignon pour le routage
struct OnionLayer {
    std::vector<uint8_t> header;
    std::vector<uint8_t> payload;
    std::vector<uint8_t> padding;
    std::string next_hop;
    uint32_t delay_ms;  // Délai aléatoire 10-1000ms
};

// Circuit complet (3 sauts minimum)
struct MixCircuit {
    NodeInfo entry_node;
    NodeInfo middle_node;
    NodeInfo exit_node;
    std::array<uint8_t, 32> session_key;
    uint64_t creation_time;
    uint64_t rotation_time;  // Rotation toutes les 20 min
    bool is_active;
};

class VrfSelector {
public:
    VrfSelector(const std::array<uint8_t, 32>& seed);
    
    // Sélection vérifiable aléatoire d'un nœud
    NodeInfo selectNode(const std::vector<NodeInfo>& nodes, const std::string& role);
    
    // Vérifier la sélection (pour audit)
    bool verifySelection(const NodeInfo& node, const std::vector<uint8_t>& proof);
    
private:
    std::array<uint8_t, 32> seed_;
    PqcCore pqc_;
};

class MixnetNode {
public:
    MixnetNode(const std::string& node_id, NodeType type);
    
    // Initialiser le nœud avec clés PQC
    void initialize();
    
    // Créer un circuit mixnet (3 sauts)
    MixCircuit createCircuit(const std::vector<NodeInfo>& available_nodes);
    
    // Construire un paquet oignon avec padding hop-by-hop
    std::vector<uint8_t> buildOnionPacket(const std::vector<uint8_t>& data, 
                                          const MixCircuit& circuit);
    
    // Déchiffrer une couche d'oignon
    std::pair<std::vector<uint8_t>, std::string> peelLayer(const std::vector<uint8_t>& onion_data);
    
    // Appliquer un délai aléatoire (10-1000ms)
    void applyRandomDelay();
    
    // Rotation automatique des circuits (toutes les 20 min)
    bool shouldRotateCircuit() const;
    
    // Générer du trafic de couverture
    std::vector<uint8_t> generateCoverTraffic();
    
    // Obtenir les informations du nœud
    const NodeInfo& getInfo() const { return info_; }
    
    // Définir comme pont polymorphe
    void setAsBridge() { info_.is_bridge = true; }
    
private:
    NodeInfo info_;
    PqcCore pqc_core_;
    PolymorphicEngine poly_engine_;
    std::unique_ptr<VrfSelector> vrf_selector_;
    std::mt19937_64 rng_;
    
    std::vector<OnionLayer> buildOnionLayers(const std::vector<uint8_t>& data,
                                             const MixCircuit& circuit);
};

class MixnetNetwork {
public:
    MixnetNetwork();
    
    // Ajouter un nœud au réseau
    void addNode(const NodeInfo& node);
    
    // Obtenir tous les nœuds disponibles
    std::vector<NodeInfo> getAvailableNodes() const;
    
    // Sélectionner des nœuds pour un nouveau circuit
    std::tuple<NodeInfo, NodeInfo, NodeInfo> selectCircuitNodes();
    
    // Mettre à jour la réputation des nœuds
    void updateReputation(const std::string& node_id, double delta);
    
    // Obtenir les statistiques du réseau
    size_t getNodeCount() const { return nodes_.size(); }
    
private:
    std::vector<NodeInfo> nodes_;
    std::mt19937_64 rng_;
};

} // namespace pq_mixnet

#endif // MIXNET_NODE_H
