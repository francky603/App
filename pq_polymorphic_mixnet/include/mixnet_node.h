#ifndef MIXNET_NODE_H
#define MIXNET_NODE_H

#include <vector>
#include <string>
#include <random>
#include <memory>
#include <map>
#include <set>
#include <chrono>
#include <functional>
#include <optional>
#include "crypto_pqc.h"
#include "polymorphic_engine.h"

namespace pqmix {

/**
 * @brief Types de nœuds dans le Mixnet
 */
enum class NodeType {
    ENTRY,    // Nœud d'entrée (Garde)
    MIDDLE,   // Nœud intermédiaire
    EXIT,     // Nœud de sortie
    BRIDGE    // Pont polymorphe (résistance censure)
};

/**
 * @brief Information sur un nœud du réseau
 */
struct NodeInfo {
    std::string id;
    std::string address;
    uint16_t port;
    NodeType type;
    std::vector<uint8_t> public_key;  // Clé publique ML-DSA pour signature
    double reputation_score = 1.0;
    std::chrono::system_clock::time_point last_seen;
    bool is_active = true;
    
    // Capacités supportées
    bool supports_pqc = true;
    bool supports_polymorphic = true;
    std::set<ProtocolMode> supported_modes;
};

/**
 * @brief Fonction VRF (Verifiable Random Function) post-quantique
 * Pour la sélection aléatoire vérifiable des nœuds
 */
class VRF {
public:
    /**
     * @brief Génère une preuve VRF et un hash aléatoire
     * @param secret_key Clé secrète du nœud
     * @param input Données d'entrée (ex: timestamp, seed)
     * @return Paire (proof, random_output)
     */
    static std::pair<std::vector<uint8_t>, std::vector<uint8_t>> 
    prove(const std::vector<uint8_t>& secret_key,
          const std::vector<uint8_t>& input);
    
    /**
     * @brief Vérifie une preuve VRF
     * @param public_key Clé publique du nœud
     * @param input Données d'entrée
     * @param proof Preuve VRF
     * @param expected_output Sortie attendue
     * @return true si la preuve est valide
     */
    static bool verify(const std::vector<uint8_t>& public_key,
                       const std::vector<uint8_t>& input,
                       const std::vector<uint8_t>& proof,
                       const std::vector<uint8_t>& expected_output);
};

/**
 * @brief Circuit Mixnet (chemin de 3+ nœuds)
 */
struct MixnetCircuit {
    std::vector<NodeInfo> nodes;  // [Entry, Middle, Exit] ou [Bridge, Entry, Middle, Exit]
    std::vector<std::array<uint8_t, 32>> shared_secrets;  // Clés par saut
    std::chrono::steady_clock::time_point created_at;
    std::chrono::milliseconds total_delay;
    
    /**
     * @brief Durée de vie du circuit (20 minutes max)
     */
    static constexpr std::chrono::minutes MAX_LIFETIME{20};
    
    bool is_expired() const {
        return std::chrono::steady_clock::now() - created_at > MAX_LIFETIME;
    }
    
    size_t hop_count() const { return nodes.size(); }
};

/**
 * @brief Gestionnaire de réseau Mixnet
 * 
 * Exigences implémentées:
 * - Sélection VRF post-quantique des nœuds
 * - Rotation toutes les 20 minutes
 * - Minimum 3 sauts (Entrée, Milieu, Sortie)
 * - Délais variables aléatoires 10-1000ms par nœud
 * - Support des ponts polymorphes
 */
class MixnetNetwork {
public:
    using NodeSelectionCallback = std::function<void(const std::vector<NodeInfo>&)>;

    MixnetNetwork(std::mt19937_64& rng);
    
    /**
     * @brief Ajoute un nœud au répertoire
     */
    void add_node(const NodeInfo& node);
    
    /**
     * @brief Supprime un nœud du répertoire
     */
    void remove_node(const std::string& node_id);
    
    /**
     * @brief Sélectionne un circuit complet via VRF
     * @param required_hops Nombre minimum de sauts (défaut: 3)
     * @param include_bridge Inclure un pont polymorphe
     * @return Circuit complet ou nullopt si échec
     */
    std::optional<MixnetCircuit> select_circuit(size_t required_hops = 3, 
                                                 bool include_bridge = false);
    
    /**
     * @brief Construit un oignon (onion routing) avec padding aléatoire
     * @param payload Message original
     * @param circuit Circuit à utiliser
     * @return Paquet oignon final
     */
    std::vector<uint8_t> build_onion(const std::vector<uint8_t>& payload,
                                     const MixnetCircuit& circuit);
    
    /**
     * @brief Déchiffre une couche de l'oignon (côté nœud)
     * @param onion_packet Paquet oillon reçu
     * @param node_secret Clé secrète du nœud actuel
     * @return Paquet déchiffré ou message final
     */
    std::vector<uint8_t> unwrap_layer(const std::vector<uint8_t>& onion_packet,
                                      const std::vector<uint8_t>& node_secret);
    
    /**
     * @brief Applique un délai aléatoire pour casser l'analyse temporelle
     * @param min_ms Délai minimum (défaut: 10ms)
     * @param max_ms Délai maximum (défaut: 1000ms)
     */
    void apply_random_delay(uint32_t min_ms = 10, uint32_t max_ms = 1000);
    
    /**
     * @brief Force la rotation des circuits après 20 minutes
     * @return Nouveau circuit sélectionné
     */
    MixnetCircuit rotate_circuits();
    
    /**
     * @brief Obtient tous les nœuds actifs
     */
    const std::map<std::string, NodeInfo>& get_nodes() const { return nodes_; }
    
    /**
     * @brief Obtient le nombre de nœuds par type
     */
    std::map<NodeType, size_t> get_node_counts() const;
    
    /**
     * @brief Simule la réception de paquets avec détection de censure
     * Les ponts polymorphes ne répondent à aucun protocole connu
     */
    bool detect_censorship(const std::string& node_address);

private:
    std::mt19937_64& rng_;
    std::map<std::string, NodeInfo> nodes_;
    std::vector<MixnetCircuit> active_circuits_;
    std::chrono::steady_clock::time_point last_rotation_;
    
    // Métriques de résistance
    size_t censorship_attempts_detected_ = 0;
    size_t successful_bridge_connections_ = 0;
    
    // Stats internes
    struct InternalStats {
        size_t circuits_rotated = 0;
    } stats_;
    
    NodeInfo select_node_by_type(NodeType type, 
                                  const std::set<std::string>& exclude = {});
    std::vector<uint8_t> generate_vrf_seed();
};

/**
 * @brief Nœud Mixnet individuel (pour implémentation serveur)
 */
class MixNode {
public:
    MixNode(const NodeInfo& info, std::mt19937_64& rng);
    
    /**
     * @brief Traite un paquet entrant
     * @param incoming_packet Paquet reçu
     * @return Paquet à transmettre ou nullopt si final
     */
    std::optional<std::vector<uint8_t>> process_packet(const std::vector<uint8_t>& incoming_packet);
    
    /**
     * @brief Ajoute un délai aléatoire avant transmission
     */
    void queue_for_transmission(const std::vector<uint8_t>& packet, 
                                std::chrono::milliseconds delay);
    
    /**
     * @brief Statistiques du nœud
     */
    struct NodeStats {
        size_t packets_processed = 0;
        size_t packets_dropped = 0;
        std::chrono::milliseconds avg_delay{0};
        std::chrono::milliseconds max_delay{0};
    };
    
    const NodeStats& get_stats() const { return stats_; }

private:
    NodeInfo info_;
    std::mt19937_64& rng_;
    NodeStats stats_;
    std::vector<uint8_t> secret_key_;  // Clé pour déchiffrer la couche
};

} // namespace pqmix

#endif // MIXNET_NODE_H
