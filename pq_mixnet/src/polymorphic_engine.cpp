#include "polymorphic_engine.h"
#include <cmath>
#include <numeric>

namespace pq_mixnet {

PolymorphicEngine::PolymorphicEngine() 
    : rng_(std::random_device{}())
    , current_mode_(ProtocolMode::WEBRTC_QUIC)
    , last_packet_time_(std::chrono::steady_clock::now()) {
    stats_ = {};
}

size_t PolymorphicEngine::generatePacketSize() {
    std::uniform_real_distribution<double> size_dist(0.0, 1.0);
    double r = size_dist(rng_);
    
    // Distribution sans mode unique identifiable
    // 15% de paquets > 2000 octets (PQC + padding)
    // < 5% de paquets < 80 octets
    // 80% de paquets moyens (80-2000 octets)
    
    if (r < 0.15) {
        // Grands paquets: 2000-4000 bytes (simulation PQC + streaming)
        std::uniform_int_distribution<size_t> large_dist(2000, 4000);
        return large_dist(rng_);
    } else if (r < 0.20) {
        // Très petits paquets: 40-79 bytes (< 5%)
        std::uniform_int_distribution<size_t> small_dist(40, 79);
        return small_dist(rng_);
    } else if (r < 0.60) {
        // Paquets moyens-bas: 200-800 bytes (QUIC/WebRTC)
        std::uniform_int_distribution<size_t> medium_low_dist(200, 800);
        return medium_low_dist(rng_);
    } else {
        // Paquets moyens-hauts: 800-2000 bytes (HTTP/2 chunks)
        std::uniform_int_distribution<size_t> medium_high_dist(800, 2000);
        return medium_high_dist(rng_);
    }
}

std::vector<uint8_t> PolymorphicEngine::generateVariableHeader(ProtocolMode mode) {
    std::uniform_int_distribution<uint16_t> dist(0, 255);
    std::vector<uint8_t> header;
    
    // Taille d'en-tête variable selon le mode (hop-by-hop random padding)
    size_t header_size;
    switch (mode) {
        case ProtocolMode::WEBRTC_QUIC:
            header_size = 32 + (dist(rng_) % 64);  // 32-96 bytes
            break;
        case ProtocolMode::HTTP2_STREAMING:
            header_size = 64 + (dist(rng_) % 128); // 64-192 bytes
            break;
        case ProtocolMode::WHITE_NOISE:
            header_size = 16 + (dist(rng_) % 256); // 16-272 bytes
            break;
        case ProtocolMode::SMTP_RELAY:
            header_size = 48 + (dist(rng_) % 96);  // 48-144 bytes
            break;
        case ProtocolMode::DNS_TUNNEL:
            header_size = 24 + (dist(rng_) % 48);  // 24-72 bytes
            break;
        default:
            header_size = 32;
    }
    
    header.resize(header_size);
    for (size_t i = 0; i < header_size; ++i) {
        header[i] = static_cast<uint8_t>(dist(rng_));
    }
    
    // Ajouter un marqueur de mode dans l'en-tête
    if (!header.empty()) {
        header[0] = static_cast<uint8_t>(mode);
    }
    
    return header;
}

std::vector<uint8_t> PolymorphicEngine::generateRandomPadding(size_t target_size) {
    std::uniform_int_distribution<uint16_t> dist(0, 255);
    std::vector<uint8_t> padding(target_size);
    
    for (size_t i = 0; i < target_size; ++i) {
        padding[i] = static_cast<uint8_t>(dist(rng_));
    }
    
    return padding;
}

std::vector<uint8_t> PolymorphicEngine::generateWhiteNoise(size_t size) {
    std::uniform_int_distribution<uint16_t> dist(0, 255);
    std::vector<uint8_t> noise(size);
    
    // Entropie maximale
    for (size_t i = 0; i < size; ++i) {
        noise[i] = static_cast<uint8_t>(dist(rng_));
    }
    
    return noise;
}

void PolymorphicEngine::updateStats(size_t packet_size) {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - last_packet_time_);
    
    // Vérifier silence > 1 seconde
    if (elapsed.count() > 1000) {
        stats_.has_silence_breach = true;
    }
    
    stats_.total_packets++;
    stats_.last_packet_time = elapsed;
    
    if (packet_size > 2000) {
        stats_.large_packets++;
    } else if (packet_size < 80) {
        stats_.small_packets++;
    } else {
        stats_.medium_packets++;
    }
    
    // Garder trace des tailles récentes pour variance
    recent_packet_sizes_.push_back(packet_size);
    if (recent_packet_sizes_.size() > 100) {
        recent_packet_sizes_.erase(recent_packet_sizes_.begin());
    }
    
    // Calculer moyenne et variance
    if (!recent_packet_sizes_.empty()) {
        double sum = std::accumulate(recent_packet_sizes_.begin(), 
                                     recent_packet_sizes_.end(), 0.0);
        stats_.avg_size = sum / recent_packet_sizes_.size();
        
        double sq_sum = 0.0;
        for (size_t s : recent_packet_sizes_) {
            sq_sum += (s - stats_.avg_size) * (s - stats_.avg_size);
        }
        stats_.variance = sq_sum / recent_packet_sizes_.size();
    }
}

PolymorphicPacket PolymorphicEngine::generatePacket(const std::vector<uint8_t>& data, 
                                                     bool is_cover_traffic) {
    PolymorphicPacket packet;
    packet.mode = current_mode_;
    packet.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    // Générer en-tête variable
    packet.header = generateVariableHeader(current_mode_);
    
    // Payload (données ou bruit blanc)
    if (is_cover_traffic) {
        packet.payload = generateWhiteNoise(generatePacketSize() / 3);
    } else {
        packet.payload = data;
    }
    
    // Calculer la taille totale cible
    size_t target_size = generatePacketSize();
    size_t current_size = packet.header.size() + packet.payload.size();
    
    // Ajouter du padding pour atteindre la taille cible
    if (current_size < target_size) {
        packet.padding = generateRandomPadding(target_size - current_size);
    }
    
    // Mettre à jour les statistiques
    updateStats(packet.totalSize());
    
    last_packet_time_ = std::chrono::steady_clock::now();
    
    return packet;
}

void PolymorphicEngine::switchProtocolMode() {
    std::uniform_int_distribution<int> dist(0, 4);
    int new_mode = dist(rng_);
    current_mode_ = static_cast<ProtocolMode>(new_mode);
}

PolymorphicPacket PolymorphicEngine::generateCoverTraffic() {
    // Générer un paquet de couverture vide
    std::vector<uint8_t> empty_data;
    return generatePacket(empty_data, true);
}

void PolymorphicEngine::applyHopPadding(PolymorphicPacket& packet, int hop_count) {
    std::uniform_int_distribution<int> pad_dist(16, 256);
    
    // Ajouter du padding aléatoire par saut
    for (int i = 0; i < hop_count; ++i) {
        size_t pad_size = pad_dist(rng_);
        auto padding = generateRandomPadding(pad_size);
        packet.padding.insert(packet.padding.end(), padding.begin(), padding.end());
    }
}

std::vector<PolymorphicPacket> PolymorphicEngine::coalesceAcks(
    const std::vector<PolymorphicPacket>& acks) {
    
    if (acks.empty()) {
        return {};
    }
    
    // Coalescer les petits ACK dans des paquets plus gros
    std::vector<PolymorphicPacket> coalesced;
    PolymorphicPacket current;
    current.mode = ProtocolMode::HTTP2_STREAMING;
    current.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    
    size_t min_coalesced_size = 200;  // Minimum 200 bytes
    
    for (const auto& ack : acks) {
        current.payload.insert(current.payload.end(), 
                               ack.payload.begin(), ack.payload.end());
        
        // Si on atteint la taille minimale, créer un paquet
        if (current.payload.size() >= min_coalesced_size) {
            current.header = generateVariableHeader(current.mode);
            current.padding = generateRandomPadding(
                generatePacketSize() - current.header.size() - current.payload.size());
            coalesced.push_back(current);
            
            // Nouveau paquet
            current = PolymorphicPacket{};
            current.mode = ProtocolMode::HTTP2_STREAMING;
            current.timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(
                std::chrono::system_clock::now().time_since_epoch()).count();
        }
    }
    
    // Packet restant
    if (!current.payload.empty()) {
        current.header = generateVariableHeader(current.mode);
        size_t target = generatePacketSize();
        if (current.header.size() + current.payload.size() < target) {
            current.padding = generateRandomPadding(
                target - current.header.size() - current.payload.size());
        }
        coalesced.push_back(current);
    }
    
    return coalesced;
}

TrafficStats PolymorphicEngine::getStats() const {
    return stats_;
}

void PolymorphicEngine::resetStats() {
    stats_ = {};
    recent_packet_sizes_.clear();
}

bool PolymorphicEngine::validatePolymorphicRequirements() const {
    if (stats_.total_packets == 0) {
        return false;
    }
    
    // Vérifier: > 10% de paquets > 1500 bytes
    double large_pct = static_cast<double>(stats_.large_packets) / stats_.total_packets;
    if (large_pct < 0.10) {
        return false;
    }
    
    // Vérifier: < 5% de paquets < 80 bytes
    double small_pct = static_cast<double>(stats_.small_packets) / stats_.total_packets;
    if (small_pct > 0.05) {
        return false;
    }
    
    // Vérifier: pas de silence > 1 seconde
    if (stats_.has_silence_breach) {
        return false;
    }
    
    // Vérifier: variance significative (courbe chaotique)
    if (stats_.variance < 10000.0) {  // Seuil minimal de variance
        return false;
    }
    
    return true;
}

} // namespace pq_mixnet
