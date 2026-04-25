# 🔐 PQ Mixnet - Post-Quantum Polymorphic Mixnet

Système de communication anonyme avancé respectant strictement les trois piliers: **Post-Quantique**, **Polymorphe**, et **Mixnet**.

## 📋 Table des Matières

1. [Fonctionnalités](#fonctionnalités)
2. [Architecture](#architecture)
3. [Compilation](#compilation)
4. [Utilisation](#utilisation)
5. [Validation](#validation)
6. [Structure du Projet](#structure-du-projet)

---

## Fonctionnalités

### 🔒 Cryptographie Post-Quantique
- **Échange de clés hybride**: X25519 + ML-KEM-768 (Kyber)
- **Signatures**: ML-DSA (Dilithium)
- **Handshake PQC**: Paquets > 2000 octets avec OID Kyber (0x6399)
- **Rotation des clés**: Régénération automatique < 10 minutes

### 🎭 Polymorphisme Actif
- **Distribution de tailles sans mode unique**
  - 15% de paquets > 2000 bytes (PQC + padding)
  - < 5% de paquets < 80 bytes (ACK coalescés)
  - 80% de paquets moyens (80-2000 bytes)
- **Mimétisme protocolaire dynamique**
  - Mode WebRTC/QUIC (UDP, 200-1300 bytes)
  - Mode HTTP/2 Streaming (TLS 1.3 avec bourrage vidéo)
  - Mode Bruit Blanc (entropie maximale)
  - Mode SMTP Relay & DNS Tunnel
- **Trafic de couverture continu**
  - 1-2 paquets/seconde même au repos
  - Aucun silence > 1 seconde

### 🌐 Architecture Mixnet
- **Routage oignon**: Minimum 3 sauts (Entrée, Milieu, Sortie)
- **Sélection VRF post-quantique**: Rotation toutes les 20 minutes
- **Délais aléatoires**: 10-1000ms par nœud
- **Ponts polymorphes**: Anti-censure, pas de bannière protocolaire

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    PQ Mixnet System                      │
├─────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │   Client    │  │    Mixnet    │  │    Server    │   │
│  │             │  │    Network   │  │              │   │
│  │ • PQC Core  │◄─┤              ├─►│ • PQC Core   │   │
│  │ • Poly Eng  │  │ • 12 Nodes   │  │ • Poly Eng   │   │
│  │ • Onion     │  │ • VRF Select │  │ • Multi-ctx  │   │
│  └─────────────┘  │ • Bridges    │  └──────────────┘   │
│                   └──────────────┘                      │
├─────────────────────────────────────────────────────────┤
│  Cryptographie: X25519 + ML-KEM-768 | ML-DSA            │
│  Morphing: QUIC | HTTP/2 | White Noise | SMTP | DNS     │
└─────────────────────────────────────────────────────────┘
```

---

## Compilation

### Prérequis
- C++17 compatible compiler (GCC 8+, Clang 7+, MSVC 2019+)
- CMake 3.16+ ou Make

### Linux / macOS

```bash
cd pq_mixnet

# Avec Make
make clean && make

# Avec CMake
mkdir build && cd build
cmake ..
make
```

### Windows (MinGW ou MSVC)

```bash
# MinGW
mingw32-make

# MSVC (Developer Command Prompt)
cmake -G "Visual Studio 16 2019" -B build
cmake --build build --config Release
```

### Exécutables générés
- `pq_mixnet_client` / `pq_mixnet_client.exe`
- `pq_mixnet_server` / `pq_mixnet_server.exe`

---

## Utilisation

### Lancer le Serveur

```bash
./pq_mixnet_server [options]

Options:
  -p, --port <port>      Port d'écoute (défaut: 9000)
  --no-bridges           Désactiver les ponts polymorphes
  --help                 Afficher l'aide
```

### Lancer le Client

```bash
./pq_mixnet_client [options]

Options:
  -h, --host <host>      Adresse du serveur (défaut: 127.0.0.1)
  -p, --port <port>      Port du serveur (défaut: 9000)
  --help                 Afficher l'aide
```

### Exemple de Session

```bash
# Terminal 1: Démarrer le serveur
./pq_mixnet_server -p 9000

# Terminal 2: Connecter le client
./pq_mixnet_client --host 127.0.0.1 --port 9000
```

---

## Validation

### Métriques de Conformité

Le système inclut une validation automatique des exigences:

| Test | Seuil de Réussite | Outil |
|------|-------------------|-------|
| % Paquets > 1500o | > 10% | Wireshark / Stats internes |
| % Paquets < 80o | < 5% | Wireshark / Stats internes |
| Silence réseau | < 1 seconde | I/O Graph |
| Variance du débit | Courbe chaotique | Wireshark |
| Taille handshake | > 2000 bytes | Capture réseau |
| Classification DPI | Inconnu / Multiple | NIDS |

### Interprétation des Logs

```
=== Statistiques de Trafic ===
Total paquets: 150
Paquets > 2000 bytes: 23 (15.3%)    ← Doit être > 10%
Paquets < 80 bytes: 4 (2.7%)        ← Doit être < 5%
Variance: 458923.5                  ← Doit être > 10000
Silence > 1s détecté: NON           ← Doit être NON

✅ TOUTES LES EXIGENCES POLYMORPHIQUES SONT RESPECTÉES!
```

---

## Structure du Projet

```
pq_mixnet/
├── include/
│   ├── pqqc_core.h            # Cryptographie PQC (ML-KEM, ML-DSA, X25519)
│   ├── polymorphic_engine.h   # Génération paquets polymorphes
│   ├── mixnet_node.h          # Routage oignon et VRF
│   └── network_protocol.h     # Protocole réseau complet
├── src/
│   ├── pqc_core.cpp           # Implémentation PQC
│   ├── polymorphic_engine.cpp # Moteur polymorphe
│   ├── mixnet_node.cpp        # Nœuds mixnet
│   ├── network_protocol.cpp   # Protocole réseau
│   ├── client.cpp             # Point d'entrée client
│   └── server.cpp             # Point d'entrée serveur
├── build/                     # Dossier de compilation
├── CMakeLists.txt             # Build system CMake
├── Makefile                   # Build system GNU Make
└── README.md                  # Ce fichier
```

---

## Détails Techniques

### Handshake Post-Quantique

```
Client Hello (> 2000 bytes):
├── Type message (1 byte)
├── OID Kyber 0x6399 (2 bytes)
├── Clé publique X25519 (32 bytes)
└── Clé publique ML-KEM (1184 bytes)

Server Hello (> 1200 bytes):
├── Type message (1 byte)
├── OID Kyber confirmé (2 bytes)
├── Clé publique X25519 serveur (32 bytes)
└── Clé publique ML-KEM serveur (1184 bytes)
```

### Structure Paquet Polymorphe

```
┌─────────────────────────────────────┐
│ Header Variable (16-272 bytes)      │
├─────────────────────────────────────┤
│ Payload Chiffré (variable)          │
├─────────────────────────────────────┤
│ Padding Aléatoire (variable)        │
└─────────────────────────────────────┘
         Total: 40 - 4000 bytes
```

---

## Sécurité et Limitations

⚠️ **Note Importante**: Cette implémentation est une **démonstration fonctionnelle**. Pour un déploiement en production:

1. Remplacer les simulations cryptographiques par:
   - [liboqs](https://github.com/open-quantum-safe/liboqs) pour ML-KEM/ML-DSA
   - libsodium pour X25519
   - OpenSSL ou BoringSSL pour AES-GCM

2. Implémenter un vrai routage réseau (sockets, TCP/UDP)

3. Ajouter une gestion robuste des erreurs

4. Effectuer un audit de sécurité complet

---

## Licence

Ce projet est fourni à des fins éducatives et de recherche.

---

## Crédits

Implémentation basée sur les spécifications:
- NIST FIPS 203 (ML-KEM/Kyber)
- NIST FIPS 204 (ML-DSA/Dilithium)
- Curve25519 (RFC 7748)
- Concepts Mixnet (Loopix, Sphinx)
