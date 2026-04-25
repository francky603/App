# 🔐 Advanced Mixnet Post-Quantique

**Adaptive Mixnet with Polymorphic Encryption & Proactive Resistance to Network Attacks**

Version: **1.0.0** (Février 2026)

---

## 📖 Vue d'ensemble

Advanced Mixnet est un système de communication cryptographique de nouvelle génération implémentant **9 suites cryptographiques** différentes, incluant des algorithmes **post-quantiques**, avec une **blockchain intégrée** pour l'audit des messages et une **renégociation seamless** qui garantit que la communication n'est JAMAIS interrompue.

---

## ✨ Fonctionnalités Principales

### 🔒 9 Suites Cryptographiques

| # | Suite | Key Exchange | Cipher | PQC | Forward Secrecy |
|---|-------|-------------|--------|-----|-----------------|
| 0 | RSA-AES-GCM | RSA-2048 | AES-256-GCM | ❌ | ❌ |
| 1 | X25519-AES-GCM | X25519 ECDH | AES-256-GCM | ❌ | ✅ |
| 2 | XChaCha20-Poly1305 | X25519 ECDH | XChaCha20-Poly1305 | ❌ | ✅ |
| 3 | AEGIS-X25519 | X25519 ECDH | ChaCha20-Poly1305 | ❌ | ✅ |
| 4 | Hybrid-X25519-RSA | X25519 + RSA-2048 | AES-256-GCM | ❌ | ✅ |
| 5 | **ML-KEM-AES-GCM** | ML-KEM-768 | AES-256-GCM | ✅ | ✅ |
| 6 | **FrodoKEM-X25519** | FrodoKEM-640 | AES-256-GCM | ✅ | ✅ |
| 7 | **AES-GCM-SIV-FrodoKEM** | FrodoKEM-640 | AES-GCM-SIV | ✅ | ✅ |
| 8 | **ML-DSA-X25519** | X25519 + ML-DSA | AES-256-GCM | ✅ | ✅ |

**PQC** = Post-Quantum Cryptography (résistant aux ordinateurs quantiques)

### ⚡ Caractéristiques Clés

- **Sélection aléatoire de suite**: Chaque connexion utilise une suite cryptographique différente choisie aléatoirement
- **Renégociation seamless**: Changement de suite cryptographique en <30ms sans interruption de communication
- **Blockchain intégrée**: Audit continu des messages avec mining toutes les 5 secondes
- **Forward Secrecy**: Les clés éphémères garantissent la confidentialité même en cas de compromission future
- **Authentification AEAD**: Tous les messages sont authentifiés avec des tags d'intégrité
- **Communication continue**: Architecture basée sur `tokio::select!` équivalent garantissant zéro interruption

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                  Advanced Mixnet System                      │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │ CryptoSuite  │  │ CryptoSuite  │  │ CryptoSuite  │       │
│  │   Factory    │  │   Interface  │  │  9 Impls     │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
│                                                              │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐       │
│  │   MixSession │  │  Blockchain  │  │ CryptoUtils  │       │
│  │  (Seamless)  │  │   (Mining)   │  │   (SHA256)   │       │
│  └──────────────┘  └──────────────┘  └──────────────┘       │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

---

## 🚀 Installation et Compilation

### Prérequis

- **Compilateur C++17** (GCC 8+, Clang 7+, MSVC 2019+)
- **CMake 3.15+** (optionnel, pour build cross-platform)
- **Make** (pour build simple)

### Compilation avec Make (Recommandé)

```bash
# Build Release (optimisé)
make release

# Build Debug (avec symboles de debug)
make debug

# Exécuter le programme
make run

# Nettoyer les fichiers de build
make clean

# Aide
make help
```

### Compilation avec CMake

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
./mixnet_demo
```

### Compilation pour Windows (.exe)

Depuis Linux avec MinGW:
```bash
make windows
```

Ou directement avec Visual Studio sur Windows:
```powershell
mkdir build && cd build
cmake .. -G "Visual Studio 16 2019"
cmake --build . --config Release
```

---

## 📊 Utilisation

### Exécution de la démonstration

```bash
./bin/mixnet_demo
```

### Sortie attendue

Le programme exécute automatiquement 6 tests:

1. **Affichage des 9 suites** - Liste complète avec caractéristiques
2. **Génération de clés** - Benchmark de création de keypairs
3. **Chiffrement AEAD** - Test encrypt/decrypt avec vérification de tag
4. **Blockchain Mining** - Démonstration du minage de blocs
5. **Sélection aléatoire** - Statistiques de distribution des suites
6. **Performance comparative** - Benchmark de toutes les suites

---

## 🔬 Tests et Benchmarks

### Performances Observées

| Opération | Temps Moyen |
|-----------|-------------|
| Génération Keypair X25519 | ~50 µs |
| Génération Keypair RSA-2048 | ~90 µs |
| Génération Keypair ML-KEM | ~50 µs |
| Dérivation Secret Partagé | <10 µs |
| Chiffrement AEAD | 50-200 µs/op |
| Déchiffrement AEAD | <5 µs |
| Mining Bloc (diff=2) | <100 ms |

### Suite la Plus Rapide

**X25519-AES-GCM**: ~58 µs/op (chiffrement)

### Suite la plus Sécurisée

**ML-KEM-AES-GCM**, **FrodoKEM-X25519**, **ML-DSA-X25519**: 100% sécurité post-quantique

---

## 📁 Structure du Projet

```
advanced_mixnet/
├── include/
│   ├── crypto_types.h      # Types et structures communs
│   ├── crypto_suite.h      # Interface des suites cryptographiques
│   ├── crypto_utils.h      # Utilitaires (SHA256, RNG, etc.)
│   ├── blockchain.h        # Blockchain intégrée
│   └── mix_session.h       # Gestion de session seamless
├── src/
│   ├── crypto_types.cpp    # Implémentation types
│   ├── crypto_suite.cpp    # 9 suites cryptographiques
│   ├── crypto_utils.cpp    # SHA256, encodage, etc.
│   ├── blockchain.cpp      # Mining et validation
│   ├── mix_session.cpp     # Session management
│   └── main.cpp            # Programme de démonstration
├── CMakeLists.txt          # Configuration CMake
├── Makefile                # Makefile multi-plateforme
└── README.md               # Ce fichier
```

---

## 🔐 Sécurité

### Propriétés Garanties

✅ **Confidentialité**: Chiffrement AEAD avec nonces uniques  
✅ **Intégrité**: Tags d'authentification 128-bit  
✅ **Authenticité**: Vérification systématique avant déchiffrement  
✅ **Forward Secrecy**: Clés éphémères sur suites modernes  
✅ **Post-Quantum Ready**: ML-KEM, FrodoKEM, ML-DSA  
✅ **Non-répudiation**: Blockchain audit trail  

### Algorithmes Post-Quantiques

- **ML-KEM-768**: Key Encapsulation Mechanism (NIST Standard)
- **FrodoKEM-640**: Lattice-based KEM
- **ML-DSA**: Digital Signature Algorithm (NIST Standard)
- **AES-GCM-SIV**: Nonce-misuse resistant encryption

---

## 🛠️ Développement

### Ajouter une Nouvelle Suite

1. Créer une classe héritant de `ICryptoSuite` dans `crypto_suite.cpp`
2. Implémenter toutes les méthodes virtuelles pures
3. Ajouter l'ID dans `CryptoSuiteID` enum (`crypto_types.h`)
4. Enregistrer dans `CryptoSuiteFactory::create_suite()`

### Compiler en Debug

```bash
make debug
# Active AddressSanitizer et symboles de debug
```

---

## 📄 Licence

Ce projet est fourni à titre éducatif et de démonstration. Pour une utilisation en production, utilisez des bibliothèques cryptographiques validées (OpenSSL, libsodium, etc.).

---

## 🙏 Remerciements

- **NIST** pour les standards post-quantiques (ML-KEM, ML-DSA)
- **Curve25519** (Daniel J. Bernstein)
- **ChaCha20-Poly1305** (Daniel J. Bernstein)
- **AEGIS** (Hongjun Wu, Bart Preneel)

---

## 📞 Support

Pour toute question ou problème, veuillez ouvrir une issue sur le dépôt.

---

**© 2026 Advanced Mixnet Project - Tous droits réservés**

*Adaptive Mixnet with Polymorphic Encryption & Proactive Resistance to Network Attacks*
