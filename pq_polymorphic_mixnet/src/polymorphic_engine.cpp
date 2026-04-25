#include "polymorphic_engine.h"
#include <cstring>
#include <algorithm>
#include <numeric>

namespace pqmix {

// ============================================================================
// MixnetHeader Implementation
// ============================================================================

std::vector<uint8_t> MixnetHeader::serialize() const {
    std::vector<uint8_t> data;
    
    // Version (1 byte)
    data.push_back(version);
    
    // Flags (1 byte)
    data.push_back(flags);
    
    // Hop count (2 bytes, little-endian)
    data.push_back(hop_count & 0xFF);
    data.push_back((hop_count >> 8) & 0xFF);
    
    // Header size (2 bytes)
    data.push_back(header_size & 0xFF);
    data.push_back((header_size >> 8) & 0xFF);
    
    // Delay ms (4 bytes)
    for (int i = 0; i < 4; ++i) {
        data.push_back((delay_ms >> (i * 8)) & 0xFF);
    }
    
    // Ephemeral key (variable)
    uint32_t key_size = static_cast<uint32_t>(ephemeral_key.size());
    for (int i = 0; i < 4; ++i) {
        data.push_back((key_size >> (i * 8)) & 0xFF);
    }
    data.insert(data.end(), ephemeral_key.begin(), ephemeral_key.end());
    
    // Padding (variable)
    uint32_t pad_size = static_cast<uint32_t>(padding.size());
    for (int i = 0; i < 4; ++i) {
        data.push_back((pad_size >> (i * 8)) & 0xFF);
    }
    data.insert(data.end(), padding.begin(), padding.end());
    
    return data;
}

MixnetHeader MixnetHeader::deserialize(const std::vector<uint8_t>& data) {
    MixnetHeader header;
    size_t offset = 0;
    
    if (data.size() < 10) return header;
    
    header.version = data[offset++];
    header.flags = data[offset++];
    
    header.hop_count = data[offset] | (data[offset + 1] << 8);
    offset += 2;
    
    header.header_size = data[offset] | (data[offset + 1] << 8);
    offset += 2;
    
    header.delay_ms = 0;
    for (int i = 0; i < 4 && offset < data.size(); ++i, ++offset) {
        header.delay_ms |= static_cast<uint32_t>(data[offset]) << (i * 8);
    }
    
    // Ephemeral key size
    if (offset + 4 <= data.size()) {
        uint32_t key_size = 0;
        for (int i = 0; i < 4; ++i) {
            key_size |= static_cast<uint32_t>(data[offset + i]) << (i * 8);
        }
        offset += 4;
        
        for (size_t i = 0; i < key_size && offset < data.size(); ++i, ++offset) {
            header.ephemeral_key.push_back(data[offset]);
        }
    }
    
    // Padding size
    if (offset + 4 <= data.size()) {
        uint32_t pad_size = 0;
        for (int i = 0; i < 4; ++i) {
            pad_size |= static_cast<uint32_t>(data[offset + i]) << (i * 8);
        }
        offset += 4;
        
        for (size_t i = 0; i < pad_size && offset < data.size(); ++i, ++offset) {
            header.padding.push_back(data[offset]);
        }
    }
    
    return header;
}

MixnetHeader MixnetHeader::create_polymorphic(std::mt19937_64& rng, size_t min_hops) {
    MixnetHeader header;
    std::uniform_int_distribution<size_t> hop_dist(min_hops, 5);
    std::uniform_int_distribution<size_t> delay_dist(10, 1000);
    std::uniform_int_distribution<size_t> pad_dist(32, 512);
    std::uniform_int_distribution<uint16_t> byte_dist(0, 255);
    
    header.hop_count = static_cast<uint16_t>(hop_dist(rng));
    header.delay_ms = static_cast<uint32_t>(delay_dist(rng));
    header.header_size = static_cast<uint16_t>(64 + pad_dist(rng));
    
    // Clé éphémère par saut (32 bytes par saut)
    size_t key_total_size = header.hop_count * 32;
    header.ephemeral_key.resize(key_total_size);
    for (size_t i = 0; i < key_total_size; ++i) {
        header.ephemeral_key[i] = static_cast<uint8_t>(byte_dist(rng));
    }
    
    // Padding aléatoire pour polymorphisme
    size_t pad_size = pad_dist(rng);
    header.padding.resize(pad_size);
    for (size_t i = 0; i < pad_size; ++i) {
        header.padding[i] = static_cast<uint8_t>(byte_dist(rng));
    }
    
    return header;
}

// ============================================================================
// PolymorphicEngine Implementation
// ============================================================================

PolymorphicEngine::PolymorphicEngine(std::mt19937_64& rng)
    : rng_(rng)
    , current_mode_(ProtocolMode::WEBRTC_QUIC)
    , previous_mode_(ProtocolMode::WEBRTC_QUIC)
    , last_packet_time_(std::chrono::steady_clock::now())
    , last_mode_switch_(std::chrono::steady_clock::now()) {
}

std::vector<uint8_t> PolymorphicEngine::generate_packet(const std::vector<uint8_t>& payload) {
    auto now = std::chrono::steady_clock::now();
    last_packet_time_ = now;
    
    // Vérifier si on doit changer de mode
    if (should_switch_mode()) {
        std::uniform_int_distribution<int> mode_dist(0, 4);
        auto new_mode = static_cast<ProtocolMode>(mode_dist(rng_));
        switch_mode(new_mode);
    }
    
    // Générer le paquet selon le mode actuel
    std::vector<uint8_t> packet;
    
    switch (current_mode_) {
        case ProtocolMode::WEBRTC_QUIC:
            packet = generate_webrtc_packet(payload);
            break;
        case ProtocolMode::HTTP2_STREAMING:
            packet = generate_http2_packet(payload);
            break;
        case ProtocolMode::WHITE_NOISE:
            packet = generate_white_noise_packet(payload);
            break;
        case ProtocolMode::HTTPS_BROWSING:
            packet = generate_https_packet(payload);
            break;
        case ProtocolMode::VIDEO_CALL:
            packet = generate_videocall_packet(payload);
            break;
    }
    
    update_stats(packet.size());
    return packet;
}

void PolymorphicEngine::switch_mode(ProtocolMode new_mode) {
    if (new_mode != current_mode_) {
        previous_mode_ = current_mode_;
        current_mode_ = new_mode;
        last_mode_switch_ = std::chrono::steady_clock::now();
    }
}

std::vector<uint8_t> PolymorphicEngine::generate_cover_traffic() {
    // Génère un paquet de trafic de couverture pour éviter les silences
    std::uniform_int_distribution<size_t> size_dist(200, 1500);
    std::uniform_int_distribution<uint16_t> byte_dist(0, 255);
    
    size_t target_size = size_dist(rng_);
    std::vector<uint8_t> cover_packet(target_size);
    
    for (size_t i = 0; i < target_size; ++i) {
        cover_packet[i] = static_cast<uint8_t>(byte_dist(rng_));
    }
    
    update_stats(target_size);
    return cover_packet;
}

size_t PolymorphicEngine::calculate_optimal_size(size_t base_size) {
    // Évite les tailles problématiques pour DPI
    
    // Interdiction: 40-79 octets (ACK TCP purs)
    if (base_size >= 40 && base_size <= 79) {
        // Force vers une taille plus grande
        std::uniform_int_distribution<size_t> dist(200, 400);
        return dist(rng_);
    }
    
    // Favorise > 2000 octets pour PQC proof (15% minimum)
    if (should_force_large_packet()) {
        std::uniform_int_distribution<size_t> dist(2000, 3500);
        return std::max(base_size, dist(rng_));
    }
    
    // Variation continue pour éviter le mode unique
    std::uniform_int_distribution<int> variance(-100, 100);
    int adjusted = static_cast<int>(base_size) + variance(rng_);
    return static_cast<size_t>(std::max(200, adjusted));
}

std::vector<uint8_t> PolymorphicEngine::add_hop_padding(const std::vector<uint8_t>& data,
                                                         size_t min_padding,
                                                         size_t max_padding) {
    std::uniform_int_distribution<size_t> pad_dist(min_padding, max_padding);
    std::uniform_int_distribution<uint16_t> byte_dist(0, 255);
    
    size_t pad_size = pad_dist(rng_);
    std::vector<uint8_t> result;
    result.reserve(data.size() + pad_size);
    
    // Padding avant
    size_t pre_pad = pad_size / 2;
    for (size_t i = 0; i < pre_pad; ++i) {
        result.push_back(static_cast<uint8_t>(byte_dist(rng_)));
    }
    
    // Données originales
    result.insert(result.end(), data.begin(), data.end());
    
    // Padding après
    for (size_t i = 0; i < pad_size - pre_pad; ++i) {
        result.push_back(static_cast<uint8_t>(byte_dist(rng_)));
    }
    
    return result;
}

std::vector<uint8_t> PolymorphicEngine::coalesce_acks(const std::vector<std::vector<uint8_t>>& acks) {
    if (acks.empty()) {
        return generate_cover_traffic();
    }
    
    // Concatène tous les ACK
    std::vector<uint8_t> coalesced;
    for (const auto& ack : acks) {
        coalesced.insert(coalesced.end(), ack.begin(), ack.end());
    }
    
    // Si toujours trop petit, ajoute du padding
    if (coalesced.size() < 200) {
        return add_hop_padding(coalesced, 200 - coalesced.size(), 400);
    }
    
    return coalesced;
}

bool PolymorphicEngine::validate_polymorphic_requirements() const {
    // Vérifie les exigences:
    // - < 5% de paquets < 80 octets
    // - > 10% de paquets > 1500 octets
    // - > 15% de paquets > 2000 octets (optionnel mais recommandé)
    
    if (stats_.total_packets < 100) {
        return true;  // Pas assez de données pour valider
    }
    
    double small_pct = stats_.get_small_percentage();
    double large_pct = stats_.get_large_percentage();
    
    bool small_ok = small_pct < 5.0;
    bool large_ok = large_pct > 10.0;
    
    return small_ok && large_ok;
}

// Générateurs spécifiques par mode

std::vector<uint8_t> PolymorphicEngine::generate_webrtc_packet(const std::vector<uint8_t>& payload) {
    // WebRTC/QUIC: UDP, tailles variables 200-1300o
    std::uniform_int_distribution<size_t> size_dist(200, 1300);
    std::uniform_int_distribution<uint16_t> byte_dist(0, 255);
    
    size_t target_size = std::max(payload.size() + 64, size_dist(rng_));
    target_size = std::min(target_size, size_t(1300));
    
    std::vector<uint8_t> packet;
    
    // En-tête QUIC simulé (variable)
    std::uniform_int_distribution<size_t> header_dist(20, 50);
    size_t header_size = header_dist(rng_);
    for (size_t i = 0; i < header_size; ++i) {
        packet.push_back(static_cast<uint8_t>(byte_dist(rng_)));
    }
    
    // Payload
    packet.insert(packet.end(), payload.begin(), payload.end());
    
    // Padding pour atteindre la taille cible
    while (packet.size() < target_size) {
        packet.push_back(static_cast<uint8_t>(byte_dist(rng_)));
    }
    
    return packet;
}

std::vector<uint8_t> PolymorphicEngine::generate_http2_packet(const std::vector<uint8_t>& payload) {
    // HTTP/2 Streaming: TLS 1.3 avec bourrage vidéo
    std::uniform_int_distribution<size_t> size_dist(500, 2500);
    std::uniform_int_distribution<uint16_t> byte_dist(0, 255);
    
    size_t target_size = size_dist(rng_);
    
    std::vector<uint8_t> packet;
    
    // En-tête HTTP/2 frame (9 bytes) + TLS record (5 bytes)
    for (int i = 0; i < 14; ++i) {
        packet.push_back(static_cast<uint8_t>(byte_dist(rng_)));
    }
    
    // Payload ou simulation de chunk vidéo
    if (!payload.empty()) {
        packet.insert(packet.end(), payload.begin(), payload.end());
    } else {
        // Simulation de données vidéo compressées
        std::uniform_int_distribution<size_t> video_chunk(400, 2000);
        size_t video_size = video_chunk(rng_);
        for (size_t i = 0; i < video_size; ++i) {
            packet.push_back(static_cast<uint8_t>(byte_dist(rng_)));
        }
    }
    
    // Padding final
    while (packet.size() < target_size) {
        packet.push_back(static_cast<uint8_t>(byte_dist(rng_)));
    }
    
    return packet;
}

std::vector<uint8_t> PolymorphicEngine::generate_white_noise_packet(const std::vector<uint8_t>& payload) {
    // Bruit blanc: entropie maximale, aucune structure
    std::uniform_int_distribution<size_t> size_dist(300, 3000);
    std::uniform_int_distribution<uint16_t> byte_dist(0, 255);
    
    size_t target_size = size_dist(rng_);
    std::vector<uint8_t> packet(target_size);
    
    for (size_t i = 0; i < target_size; ++i) {
        packet[i] = static_cast<uint8_t>(byte_dist(rng_));
    }
    
    return packet;
}

std::vector<uint8_t> PolymorphicEngine::generate_https_packet(const std::vector<uint8_t>& payload) {
    // HTTPS Browsing: simulation navigation web
    std::uniform_int_distribution<size_t> size_dist(200, 1800);
    std::uniform_int_distribution<uint16_t> byte_dist(0, 255);
    
    size_t target_size = size_dist(rng_);
    
    std::vector<uint8_t> packet;
    
    // TLS record header (5 bytes)
    packet.push_back(0x17);  // Application Data
    packet.push_back(0x03);  // TLS 1.2+
    packet.push_back(0x03);
    for (int i = 0; i < 2; ++i) {
        packet.push_back(static_cast<uint8_t>(byte_dist(rng_)));
    }
    
    // Payload ou données de navigation simulées
    if (!payload.empty()) {
        packet.insert(packet.end(), payload.begin(), payload.end());
    }
    
    // Padding
    while (packet.size() < target_size) {
        packet.push_back(static_cast<uint8_t>(byte_dist(rng_)));
    }
    
    return packet;
}

std::vector<uint8_t> PolymorphicEngine::generate_videocall_packet(const std::vector<uint8_t>& payload) {
    // Video Call: paquets réguliers imitant RTP
    std::uniform_int_distribution<size_t> size_dist(400, 1400);
    std::uniform_int_distribution<uint16_t> byte_dist(0, 255);
    
    size_t target_size = size_dist(rng_);
    
    std::vector<uint8_t> packet;
    
    // RTP header simulé (12 bytes)
    packet.push_back(0x80);  // Version 2
    packet.push_back(static_cast<uint8_t>(byte_dist(rng_)));  // Payload type
    for (int i = 0; i < 10; ++i) {
        packet.push_back(static_cast<uint8_t>(byte_dist(rng_)));
    }
    
    // Données audio/vidéo
    if (!payload.empty()) {
        packet.insert(packet.end(), payload.begin(), payload.end());
    }
    
    // Padding
    while (packet.size() < target_size) {
        packet.push_back(static_cast<uint8_t>(byte_dist(rng_)));
    }
    
    return packet;
}

// Utilitaires

size_t PolymorphicEngine::generate_size_for_mode(ProtocolMode mode) {
    std::uniform_int_distribution<size_t> dist_200_1300(200, 1300);
    std::uniform_int_distribution<size_t> dist_500_2500(500, 2500);
    std::uniform_int_distribution<size_t> dist_300_3000(300, 3000);
    std::uniform_int_distribution<size_t> dist_200_1800(200, 1800);
    std::uniform_int_distribution<size_t> dist_400_1400(400, 1400);
    
    switch (mode) {
        case ProtocolMode::WEBRTC_QUIC: return dist_200_1300(rng_);
        case ProtocolMode::HTTP2_STREAMING: return dist_500_2500(rng_);
        case ProtocolMode::WHITE_NOISE: return dist_300_3000(rng_);
        case ProtocolMode::HTTPS_BROWSING: return dist_200_1800(rng_);
        case ProtocolMode::VIDEO_CALL: return dist_400_1400(rng_);
        default: return dist_200_1300(rng_);
    }
}

void PolymorphicEngine::update_stats(size_t packet_size) {
    stats_.total_packets++;
    
    if (packet_size < 80) {
        stats_.packets_small++;
        consecutive_small_packets_++;
    } else {
        consecutive_small_packets_ = 0;
    }
    
    if (packet_size > 1500) {
        stats_.packets_large++;
    }
    
    if (packet_size > 2000) {
        stats_.packets_huge++;
        packets_since_last_large_ = 0;
    } else {
        packets_since_last_large_++;
    }
    
    if (packet_size >= 80 && packet_size <= 1500) {
        stats_.packets_medium++;
    }
}

bool PolymorphicEngine::should_force_large_packet() const {
    // Force un grand paquet si:
    // - On n'a pas envoyé de gros paquet depuis longtemps
    // - Ou si le pourcentage de gros paquets est trop bas
    if (packets_since_last_large_ > 20) {
        return true;  // Au moins 1 gros paquet toutes les 20 transmissions
    }
    
    if (stats_.total_packets > 50 && stats_.get_huge_percentage() < 15.0) {
        return true;  // Rattrapage pour atteindre 15%
    }
    
    // Probabilité aléatoire pour atteindre ~15-20%
    std::uniform_int_distribution<int> dist(0, 100);
    return dist(const_cast<std::mt19937_64&>(rng_)) < 18;  // 18% de chance
}

bool PolymorphicEngine::should_switch_mode() const {
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - last_mode_switch_).count();
    
    // Change de mode toutes les 5-15 secondes pour le mimétisme
    if (elapsed < 5) return false;
    
    std::uniform_int_distribution<int> dist(0, 100);
    return dist(const_cast<std::mt19937_64&>(rng_)) < 30;  // 30% de chance après 5s
}

} // namespace pqmix
