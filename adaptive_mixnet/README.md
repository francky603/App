# Adaptive Mixnet with Polymorphic Encryption

## Design and Analysis of an Adaptive Mixnet with Polymorphic Encryption for Proactive Resistance to Network Attacks

This project implements a sophisticated adaptive mixnet system featuring polymorphic encryption capabilities designed to provide proactive resistance against various network attacks.

## Features

### Core Components

1. **Polymorphic Encryption Module**
   - Multiple encryption algorithms (XOR, Rotation, Substitution, Composite)
   - Dynamic algorithm switching based on threat levels
   - Performance statistics tracking
   - Key management and rotation

2. **Mix Node System**
   - Message batching and shuffling
   - Queue management with configurable limits
   - Threat-aware processing
   - Health monitoring and reporting

3. **Adaptive Mixnet Network**
   - Multi-node network topology
   - Dynamic path selection
   - Real-time threat assessment
   - Attack simulation and resistance
   - Comprehensive statistics collection

### Security Features

- **Proactive Threat Response**: Automatically switches to stronger encryption when threats are detected
- **Dynamic Routing**: Routes messages through healthy nodes, avoiding compromised paths
- **Message Padding**: Prevents traffic analysis through uniform message sizes
- **Algorithm Diversity**: Multiple encryption methods prevent pattern recognition
- **Real-time Monitoring**: Continuous network health assessment

## Project Structure

```
adaptive_mixnet/
├── CMakeLists.txt          # CMake build configuration
├── Makefile                # GNU Make build configuration
├── README.md               # This file
├── include/
│   ├── polymorphic_encryption.h
│   ├── mix_node.h
│   └── adaptive_mixnet.h
└── src/
    ├── polymorphic_encryption.cpp
    ├── mix_node.cpp
    ├── adaptive_mixnet.cpp
    └── main.cpp
```

## Building the Project

### Using CMake

```bash
cd adaptive_mixnet
mkdir build
cd build
cmake ..
make
./AdaptiveMixnet
```

### Using Make

```bash
cd adaptive_mixnet
make          # Build the project
make run      # Build and run
make debug    # Debug build
make release  # Optimized release build
make clean    # Clean build artifacts
```

## Requirements

- C++17 compatible compiler (GCC 7+, Clang 5+, MSVC 2017+)
- CMake 3.10+ (for CMake build)
- POSIX threads support

## Usage Example

```cpp
#include "adaptive_mixnet.h"

using namespace AdaptiveMixnet;

// Configure the network
NetworkConfig config;
config.num_nodes = 5;
config.min_path_length = 2;
config.max_path_length = 4;
config.base_threat_level = 0.2;
config.monitoring_interval_ms = 500;
config.enable_logging = true;

// Create and initialize the mixnet
AdaptiveMixnet mixnet(config);
mixnet.initialize();
mixnet.start();

// Send messages
std::vector<uint8_t> payload = {'H', 'e', 'l', 'l', 'o'};
mixnet.sendMessage(payload, "destination");

// Simulate attack
mixnet.simulateAttack(0.7);

// Monitor status
mixnet.printNetworkStatus();

// Cleanup
mixnet.stop();
```

## Demonstration Output

The main program demonstrates:

1. **Polymorphic Encryption**: Shows all encryption algorithms in action
2. **Threat Adaptation**: Displays algorithm selection based on threat levels
3. **Network Operations**: Full mixnet operation with message passing
4. **Attack Resistance**: Progressive attack simulation showing adaptive response

## Architecture Details

### Encryption Algorithms

| Algorithm | Security Level | Performance | Use Case |
|-----------|---------------|-------------|----------|
| XOR Cipher | Low | Very Fast | Low threat environments |
| Rotation Cipher | Medium | Fast | Moderate threat levels |
| Substitution Cipher | High | Medium | Elevated threats |
| Composite Cipher | Maximum | Slower | Critical threat situations |

### Threat Response Matrix

| Threat Level | Algorithm | Behavior |
|--------------|-----------|----------|
| 0.0 - 0.25 | XOR | Normal operation |
| 0.25 - 0.50 | Rotation | Increased vigilance |
| 0.50 - 0.75 | Substitution | Enhanced security |
| 0.75 - 1.00 | Composite | Maximum protection |

## Analysis Considerations

### Performance Metrics
- Message throughput (messages/second)
- End-to-end latency
- Algorithm switch frequency
- Node utilization

### Security Metrics
- Attack detection time
- Response effectiveness
- Message delivery rate under attack
- Node survival rate

### Trade-offs
- Security vs. Performance
- Latency vs. Anonymity
- Resource usage vs. Protection level

## License

This project is provided for educational and research purposes.

## Authors

Adaptive Mixnet Research Project

## References

1. Chaum, D. (1981). "Untraceable Electronic Mail, Return Addresses, and Digital Pseudonyms"
2. Danezis, G., et al. (2005). "Traffic Analysis of the SSL/TLS Protocol"
3. Kesdogan, D., et al. (2002). "Stop-and-Go-MIXes Providing Probabilistic Anonymity"
