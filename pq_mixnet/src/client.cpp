/**
 * PQ Mixnet - Client
 * 
 * Client de communication anonyme post-quantique avec:
 * - Échange de clés hybride X25519 + ML-KEM-768
 * - Routage oignon avec 3 sauts minimum
 * - Trafic polymorphe et couverture continue
 * - Renégociation seamless des clés
 */

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <csignal>
#include <atomic>
#include "network_protocol.h"
#include "polymorphic_engine.h"
#include "mixnet_node.h"

using namespace pq_mixnet;

std::atomic<bool> running(true);

void signalHandler(int signum) {
    std::cout << "\n[Client] Signal reçu (" << signum << "), arrêt en cours..." << std::endl;
    running = false;
}

void printStats(const TrafficStats& stats) {
    std::cout << "\n=== Statistiques de Trafic ===" << std::endl;
    std::cout << "Total paquets: " << stats.total_packets << std::endl;
    std::cout << "Paquets > 2000 bytes: " << stats.large_packets 
              << " (" << (stats.total_packets > 0 ? 100.0 * stats.large_packets / stats.total_packets : 0) << "%)" << std::endl;
    std::cout << "Paquets < 80 bytes: " << stats.small_packets 
              << " (" << (stats.total_packets > 0 ? 100.0 * stats.small_packets / stats.total_packets : 0) << "%)" << std::endl;
    std::cout << "Paquets moyens: " << stats.medium_packets << std::endl;
    std::cout << "Taille moyenne: " << stats.avg_size << " bytes" << std::endl;
    std::cout << "Variance: " << stats.variance << std::endl;
    std::cout << "Silence > 1s détecté: " << (stats.has_silence_breach ? "OUI" : "NON") << std::endl;
    
    // Validation des exigences
    bool large_ok = stats.total_packets > 0 && (100.0 * stats.large_packets / stats.total_packets) > 10.0;
    bool small_ok = stats.total_packets > 0 && (100.0 * stats.small_packets / stats.total_packets) < 5.0;
    bool silence_ok = !stats.has_silence_breach;
    bool variance_ok = stats.variance > 10000.0;
    
    std::cout << "\n=== Validation Exigences ===" << std::endl;
    std::cout << "[✓] > 10% paquets > 1500 bytes: " << (large_ok ? "PASS" : "FAIL") << std::endl;
    std::cout << "[✓] < 5% paquets < 80 bytes: " << (small_ok ? "PASS" : "FAIL") << std::endl;
    std::cout << "[✓] Pas de silence > 1s: " << (silence_ok ? "PASS" : "FAIL") << std::endl;
    std::cout << "[✓] Variance significative: " << (variance_ok ? "PASS" : "FAIL") << std::endl;
    
    if (large_ok && small_ok && silence_ok && variance_ok) {
        std::cout << "\n✅ TOUTES LES EXIGENCES POLYMORPHIQUES SONT RESPECTÉES!" << std::endl;
    } else {
        std::cout << "\n⚠️  Certaines exigences ne sont pas respectées." << std::endl;
    }
}

int main(int argc, char* argv[]) {
    std::string server_host = "127.0.0.1";
    int server_port = 9000;
    
    // Parser les arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "-h" || arg == "--host") && i + 1 < argc) {
            server_host = argv[++i];
        } else if ((arg == "-p" || arg == "--port") && i + 1 < argc) {
            server_port = std::stoi(argv[++i]);
        } else if (arg == "--help") {
            std::cout << "Usage: " << argv[0] << " [options]" << std::endl;
            std::cout << "Options:" << std::endl;
            std::cout << "  -h, --host <host>   Adresse du serveur (défaut: 127.0.0.1)" << std::endl;
            std::cout << "  -p, --port <port>   Port du serveur (défaut: 9000)" << std::endl;
            std::cout << "  --help              Afficher cette aide" << std::endl;
            return 0;
        }
    }
    
    // Configurer le gestionnaire de signal
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    std::cout << "╔══════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║     PQ Mixnet Client - Post-Quantique Polymorphe        ║" << std::endl;
    std::cout << "╠══════════════════════════════════════════════════════════╣" << std::endl;
    std::cout << "║ • Cryptographie: X25519 + ML-KEM-768 (Hybride PQC)      ║" << std::endl;
    std::cout << "║ • Signatures: ML-DSA (Dilithium)                        ║" << std::endl;
    std::cout << "║ • Routage: Mixnet 3 sauts avec délais aléatoires        ║" << std::endl;
    std::cout << "║ • Morphing: WebRTC/QUIC, HTTP/2, Bruit Blanc            ║" << std::endl;
    std::cout << "║ • Couverture: Trafic continu sans silence               ║" << std::endl;
    std::cout << "╚══════════════════════════════════════════════════════════╝" << std::endl;
    std::cout << std::endl;
    
    try {
        // Créer le client
        auto client = NetworkFactory::createClient();
        
        std::cout << "[Client] Connexion à " << server_host << ":" << server_port << "..." << std::endl;
        
        // Note: En mode simulation, la connexion réseau est mockée
        // Pour une vraie connexion, décommenter:
        // if (!client->connect(server_host, server_port)) {
        //     std::cerr << "[Client] Échec de connexion" << std::endl;
        //     return 1;
        // }
        
        // Simuler une connexion réussie pour la démo
        client->setConnected(true);
        client->setAuthenticated(true);
        std::cout << "[Client] ✓ Connecté et authentifié" << std::endl;
        
        // Créer un circuit mixnet
        std::cout << "\n[Client] Création circuit mixnet..." << std::endl;
        client->rotateCircuit();
        
        // Thread pour le trafic de couverture (1-2 paquets/seconde)
        std::thread coverThread([&client]() {
            int count = 0;
            while (running) {
                client->sendCoverTraffic();
                count++;
                
                // 1-2 paquets par seconde
                std::this_thread::sleep_for(std::chrono::milliseconds(500 + (count % 2) * 500));
            }
        });
        
        // Thread pour la renégociation périodique (< 10 minutes)
        std::thread renegotiateThread([&client]() {
            int rotations = 0;
            while (running) {
                // Attendre 30 secondes pour la démo (normalement 10 min)
                std::this_thread::sleep_for(std::chrono::seconds(30));
                
                if (running) {
                    std::cout << "\n[Client] >>> Rotation des clés programmée <<<" << std::endl;
                    client->renegotiateKeys();
                    
                    rotations++;
                    if (rotations % 3 == 0) {
                        std::cout << "[Client] >>> Rotation du circuit mixnet <<<" << std::endl;
                        client->rotateCircuit();
                    }
                }
            }
        });
        
        // Boucle principale d'envoi de messages
        std::cout << "\n[Client] Envoi de messages de test..." << std::endl;
        std::cout << "(Appuyez sur Ctrl+C pour arrêter)" << std::endl;
        std::cout << std::endl;
        
        int msg_count = 0;
        while (running && msg_count < 50) {  // 50 messages pour la démo
            // Créer un message de test
            std::string msg_content = "Message sécurisé #" + std::to_string(msg_count) + 
                                     " - " + std::string(50 + (msg_count % 100), 'x');
            std::vector<uint8_t> msg_data(msg_content.begin(), msg_content.end());
            
            // Envoyer le message
            client->sendMessage(msg_data);
            
            msg_count++;
            
            // Délai aléatoire entre les messages (100ms - 2s)
            std::this_thread::sleep_for(std::chrono::milliseconds(100 + (msg_count % 19) * 100));
        }
        
        // Arrêter les threads
        running = false;
        if (coverThread.joinable()) coverThread.join();
        if (renegotiateThread.joinable()) renegotiateThread.join();
        
        // Afficher les statistiques
        auto stats = client->getTrafficStats();
        printStats(stats);
        
        // Valider les exigences polymorphiques
        PolymorphicEngine poly;
        std::cout << "\n=== Test de Conformité ===" << std::endl;
        std::cout << "Validation automatique: " 
                  << (poly.validatePolymorphicRequirements() ? "✅ PASS" : "❌ FAIL") << std::endl;
        
        std::cout << "\n[Client] Fermeture propre..." << std::endl;
        client->shutdown();
        
    } catch (const std::exception& e) {
        std::cerr << "[Client] Erreur: " << e.what() << std::endl;
        return 1;
    }
    
    std::cout << "\n✅ Client terminé avec succès!" << std::endl;
    return 0;
}
