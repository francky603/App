#ifndef POLYMORPHIC_ENGINE_H
#define POLYMORPHIC_ENGINE_H

#include <vector>
#include <random>
#include <string>
#include <memory>
#include <chrono>
#include <functional>
#include <map>

namespace pqmix {

/**
 * @brief Modes de mimétisme protocolaire
 * Permet de basculer dynamiquement sans coupure de session
 */
enum class ProtocolMode {
    WEBRTC_QUIC,      // UDP, tailles variables 200-1300o
    HTTP2_STREAMING,  // TLS 1.3 avec bourrage vidéo
    WHITE_NOISE,      // Entropie maximale, aucune structure
    HTTPS_BROWSING,   // Simulation navigation web
    VIDEO_CALL        // Simulation appel vidéo (paquets réguliers)
};

/**
 * @brief Statistiques de trafic pour l'analyse polymorphique
 */
struct TrafficStats {
    size_t total_packets = 0;
    size_t packets_small = 0;   // < 80 octets (doit être < 5%)
    size_t packets_medium = 0;  // 80-1500 octets
    size_t packets_large = 0;   // > 1500 octets (doit être > 10%)
    size_t packets_huge = 0;    // > 2000 octets (PQC proof)
    
    double get_small_percentage() const {
        return total_packets > 0 ? (100.0 * packets_small / total_packets) : 0.0;
    }
    
    double get_large_percentage() const {
        return total_packets > 0 ? (100.0 * packets_large / total_packets) : 0.0;
    }
    
    double get_huge_percentage() const {
        return total_packets > 0 ? (100.0 * packets_huge / total_packets) : 0.0;
    }
};

/**
 * @brief Moteur polymorphique pour le camouflage actif
 * 
 * Exigences implémentées:
 * - Distribution des tailles sans mode unique
 * - < 5% de paquets < 80 octets (ACK TCP masqués)
 * - > 15% de paquets > 2000 octets
 * - Variation continue des en-têtes de routage
 * - Padding aléatoire hop-by-hop
 * - Trafic de couverture permanent (1-2 paquets/sec idle)
 */
class PolymorphicEngine {
public:
    using PacketGenerator = std::function<std::vector<uint8_t>(std::mt19937_64&)>;

    PolymorphicEngine(std::mt19937_64& rng);
    
    /**
     * @brief Génère un paquet polymorphique selon le mode actuel
     * @param payload Données utilisateur à encapsuler
     * @return Paquet final avec padding et en-têtes variables
     */
    std::vector<uint8_t> generate_packet(const std::vector<uint8_t>& payload);
    
    /**
     * @brief Change dynamiquement de mode protocolaire
     * @param new_mode Nouveau mode à adopter
     */
    void switch_mode(ProtocolMode new_mode);
    
    /**
     * @brief Obtient le mode actuel
     */
    ProtocolMode get_current_mode() const { return current_mode_; }
    
    /**
     * @brief Génère du trafic de couverture (cover traffic)
     * À appeler même en idle pour éviter les silences > 1s
     */
    std::vector<uint8_t> generate_cover_traffic();
    
    /**
     * @brief Calcule la taille optimale pour respecter les contraintes DPI
     * Évite le pic 40-79 octets, favorise > 2000 octets
     */
    size_t calculate_optimal_size(size_t base_size);
    
    /**
     * @brief Ajoute un padding aléatoire hop-by-hop
     * @param data Données à padder
     * @param min_padding Padding minimum
     * @param max_padding Padding maximum
     */
    std::vector<uint8_t> add_hop_padding(const std::vector<uint8_t>& data,
                                         size_t min_padding = 64,
                                         size_t max_padding = 512);
    
    /**
     * @brief Coalesce les petits ACK dans des paquets plus gros
     * @param acks Liste des ACK à coalescer
     * @return Paquet unique > 200 octets
     */
    std::vector<uint8_t> coalesce_acks(const std::vector<std::vector<uint8_t>>& acks);
    
    /**
     * @brief Obtient les statistiques de trafic actuelles
     */
    const TrafficStats& get_stats() const { return stats_; }
    
    /**
     * @brief Réinitialise les statistiques
     */
    void reset_stats() { stats_ = TrafficStats(); }
    
    /**
     * @brief Vérifie la conformité aux exigences polymorphiques
     * @return true si toutes les métriques sont respectées
     */
    bool validate_polymorphic_requirements() const;

private:
    std::mt19937_64& rng_;
    ProtocolMode current_mode_;
    ProtocolMode previous_mode_;
    TrafficStats stats_;
    
    std::chrono::steady_clock::time_point last_packet_time_;
    std::chrono::steady_clock::time_point last_mode_switch_;
    
    size_t consecutive_small_packets_ = 0;
    size_t packets_since_last_large_ = 0;
    
    // Générateurs spécifiques par mode
    std::vector<uint8_t> generate_webrtc_packet(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> generate_http2_packet(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> generate_white_noise_packet(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> generate_https_packet(const std::vector<uint8_t>& payload);
    std::vector<uint8_t> generate_videocall_packet(const std::vector<uint8_t>& payload);
    
    // Utilitaires
    size_t generate_size_for_mode(ProtocolMode mode);
    void update_stats(size_t packet_size);
    bool should_force_large_packet() const;
    bool should_switch_mode() const;
};

/**
 * @brief En-tête de routage Sphinx/Loopix avec padding variable
 */
struct MixnetHeader {
    uint8_t version = 0x01;
    uint8_t flags = 0x00;
    uint16_t hop_count = 3;  // Minimum 3 sauts
    uint16_t header_size;    // Variable pour polymorphisme
    uint32_t delay_ms;       // Délai aléatoire 10-1000ms
    std::vector<uint8_t> ephemeral_key;  // Clé éphémère par saut
    std::vector<uint8_t> padding;        // Padding aléatoire
    
    std::vector<uint8_t> serialize() const;
    static MixnetHeader deserialize(const std::vector<uint8_t>& data);
    
    /**
     * @brief Génère un en-tête avec taille variable pour polymorphisme
     */
    static MixnetHeader create_polymorphic(std::mt19937_64& rng, size_t min_hops = 3);
};

} // namespace pqmix

#endif // POLYMORPHIC_ENGINE_H
