/**
 * PQ Mixnet - Serveur
 * 
 * Serveur de communication anonyme post-quantique avec:
 * - Échange de clés hybride X25519 + ML-KEM-768
 * - Support de plusieurs clients simultanés
 * - Trafic polymorphe et couverture continue
 * - Ponts polymorphes anti-censure
 */

#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <csignal>
#include <atomic>
#include <mutex>
#include <map>
#include "network_protocol.h"
#include "polymorphic_engine.h"
#include "mixnet_node.h"

using namespace pq_mixnet;

std::atomic<bool> running(true);
std::mutex client_mutex;
std::map<int, std::unique_ptr<NetworkProtocol>> clients;

void signalHandler(int signum) {
    std::cout << "\n[Serveur] Signal reçu (" << signum << "), arrêt en cours..." << std::endl;
    running = false;
}

void handleClient(int client_id, NetworkProtocol* client) {
    std::cout << "[Serveur] Gestion client #" << client_id << std::endl;
    
    int msg_count = 0;
    while (running && msg_count < 30) {
        // Simuler la réception de messages
        auto msg = client->receiveMessage();
        
        if (!msg.empty()) {
            std::cout << "[Serveur] Client #" << client_id << ": message reçu (" 
                      << msg.size() << " bytes)" << std::endl;
        }
        
        // Répondre occasionnellement
        if (msg_count % 5 == 0) {
            std::string response = "Réponse du serveur #" + std::to_string(msg_count);
            std::vector<uint8_t> resp_data(response.begin(), response.end());
            client->sendMessage(resp_data);
        }
        
        msg_count++;
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    
    std::cout << "[Serveur] Client #" << client_id << " déconnecté" << std::endl;
}

int main(int argc, char* argv[]) {
    int server_port = 9000;
    bool enable_bridges = true;
    
    // Parser les arguments
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if ((arg == "-p" || arg == "--port") && i + 1 < argc) {
            server_port = std::stoi(argv[++i]);
        } else if (arg == "--no-bridges") {
            enable_bridges = false;
        } else if (arg == "--help") {
            std::cout << "Usage: " << argv[0] << " [options]" << std::endl;
            std::cout << "Options:" << std::endl;
            std::cout << "  -p, --port <port>      Port d'écoute (défaut: 9000)" << std::endl;
            std::cout << "  --no-bridges           Désactiver les ponts polymorphes" << std::endl;
            std::cout << "  --help                 Afficher cette aide" << std::endl;
            return 0;
        }
    }
    
    // Configurer le gestionnaire de signal
    signal(SIGINT, signalHandler);
    signal(SIGTERM, signalHandler);
    
    std::cout << "╔══════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║     PQ Mixnet Server - Post-Quantique Polymorphe        ║" << std::endl;
    std::cout << "╠══════════════════════════════════════════════════════════╣" << std::endl;
    std::cout << "║ • Cryptographie: X25519 + ML-KEM-768 (Hybride PQC)      ║" << std::endl;
    std::cout << "║ • Signatures: ML-DSA (Dilithium)                        ║" << std::endl;
    std::cout << "║ • Routage: Mixnet avec VRF post-quantique               ║" << std::endl;
    std::cout << "║ • Morphing: Multi-protocoles dynamique                  ║" << std::endl;
    std::cout << "║ • Ponts: Anti-censure polymorphes                       ║" << std::endl;
    std::cout << "╚══════════════════════════════════════════════════════════╝" << std::endl;
    std::cout << std::endl;
    
    try {
        // Initialiser le réseau mixnet
        MixnetNetwork network;
        
        // Ajouter des nœuds de démo
        std::cout << "[Serveur] Initialisation du réseau mixnet..." << std::endl;
        for (int i = 0; i < 12; ++i) {
            NodeInfo node;
            node.id = "mixnode_" + std::to_string(i);
            node.address = "10.0." + std::to_string(i / 4) + "." + std::to_string(100 + (i % 4));
            node.port = 9000 + i;
            node.type = static_cast<NodeType>(i % 3);
            node.reputation_score = 0.85 + (i % 5) * 0.03;
            node.is_bridge = (i % 4 == 0) && enable_bridges;
            
            if (node.is_bridge) {
                std::cout << "  + Pont polymorphe: " << node.id << std::endl;
            }
            
            network.addNode(node);
        }
        std::cout << "[Serveur] " << network.getNodeCount() << " nœuds enregistrés" << std::endl;
        
        // Créer un nœud serveur
        MixnetNode server_node("server_main", NodeType::EXIT);
        server_node.initialize();
        if (enable_bridges) {
            server_node.setAsBridge();
            std::cout << "[Serveur] ✓ Configuré comme pont polymorphe" << std::endl;
        }
        
        std::cout << "\n[Serveur] Démarrage sur le port " << server_port << "..." << std::endl;
        
        // Note: En mode simulation, le serveur est mocké
        // Pour un vrai serveur:
        // auto server = NetworkFactory::createServer(server_port);
        
        std::cout << "[Serveur] ✓ Serveur prêt (mode simulation)" << std::endl;
        std::cout << "[Serveur] En attente de connexions clients..." << std::endl;
        std::cout << std::endl;
        
        // Simuler plusieurs clients connectés
        int client_counter = 0;
        std::vector<std::thread> client_threads;
        
        // Thread pour accepter de nouveaux clients (simulation)
        std::thread acceptThread([&]() {
            while (running && client_counter < 5) {
                std::this_thread::sleep_for(std::chrono::seconds(2));
                
                if (running) {
                    client_counter++;
                    std::cout << "\n[Serveur] >>> Nouveau client connecté (#" << client_counter << ") <<<" << std::endl;
                    
                    // Créer un client simulé
                    auto client = NetworkFactory::createClient();
                    client->setConnected(true);
                    client->setAuthenticated(true);
                    
                    // Lancer un thread pour gérer ce client
                    {
                        std::lock_guard<std::mutex> lock(client_mutex);
                        clients[client_counter] = std::move(client);
                    }
                    
                    client_threads.emplace_back(handleClient, client_counter, 
                                                clients[client_counter].get());
                }
            }
        });
        
        // Thread pour le trafic de couverture global
        std::thread coverThread([&]() {
            PolymorphicEngine poly;
            int count = 0;
            
            while (running) {
                auto packet = poly.generateCoverTraffic();
                
                if (count % 10 == 0) {
                    std::cout << "[Serveur] Cover traffic: " << packet.totalSize() 
                              << " bytes (mode: " << static_cast<int>(packet.mode) << ")" << std::endl;
                }
                
                count++;
                std::this_thread::sleep_for(std::chrono::milliseconds(750));
            }
        });
        
        // Thread pour la rotation des circuits
        std::thread rotateThread([&]() {
            int rotations = 0;
            
            while (running) {
                std::this_thread::sleep_for(std::chrono::seconds(45));
                
                if (running) {
                    rotations++;
                    std::cout << "\n[Serveur] >>> Rotation automatique des circuits <<<" << std::endl;
                    
                    std::lock_guard<std::mutex> lock(client_mutex);
                    for (auto& [id, client] : clients) {
                        client->rotateCircuit();
                    }
                    
                    if (rotations % 2 == 0) {
                        std::cout << "[Serveur] Mise à jour de la réputation des nœuds..." << std::endl;
                        auto nodes = network.getAvailableNodes();
                        for (const auto& node : nodes) {
                            double delta = (node.reputation_score > 0.5) ? -0.02 : 0.05;
                            network.updateReputation(node.id, delta);
                        }
                    }
                }
            }
        });
        
        // Attendre que les threads se terminent
        acceptThread.join();
        
        // Donner du temps aux threads clients
        std::this_thread::sleep_for(std::chrono::seconds(5));
        
        running = false;
        
        if (coverThread.joinable()) coverThread.join();
        if (rotateThread.joinable()) rotateThread.join();
        
        for (auto& t : client_threads) {
            if (t.joinable()) t.join();
        }
        
        // Afficher les statistiques globales
        std::cout << "\n=== Statistiques du Serveur ===" << std::endl;
        std::cout << "Clients traités: " << client_counter << std::endl;
        std::cout << "Nœuds dans le réseau: " << network.getNodeCount() << std::endl;
        
        size_t bridge_count = 0;
        for (const auto& node : network.getAvailableNodes()) {
            if (node.is_bridge) bridge_count++;
        }
        std::cout << "Ponts polymorphes: " << bridge_count << std::endl;
        
        std::cout << "\n[Serveur] Fermeture propre..." << std::endl;
        
        {
            std::lock_guard<std::mutex> lock(client_mutex);
            for (auto& [id, client] : clients) {
                client->shutdown();
            }
            clients.clear();
        }
        
    } catch (const std::exception& e) {
        std::cerr << "[Serveur] Erreur: " << e.what() << std::endl;
        return 1;
    }
    
    std::cout << "\n✅ Serveur arrêté avec succès!" << std::endl;
    return 0;
}
