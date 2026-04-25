# ============================================================================
# Makefile pour Advanced Mixnet Post-Quantique
# Compatible Linux, macOS et Windows (MinGW)
# ============================================================================

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Wpedantic
LDFLAGS = -pthread

# Détection de la plateforme
UNAME_S := $(shell uname -s)

ifeq ($(UNAME_S),Linux)
    CXXFLAGS += -fstack-protector-strong
    LDFLAGS += -lrt
endif

ifeq ($(UNAME_S),Darwin)
    CXXFLAGS += -mmacosx-version-min=10.15
endif

# Configuration Release vs Debug
BUILD_TYPE ?= Release

ifeq ($(BUILD_TYPE),Release)
    CXXFLAGS += -O3 -DNDEBUG
    ifeq ($(UNAME_S),Linux)
        CXXFLAGS += -march=native
    endif
else
    CXXFLAGS += -g -fsanitize=address
    LDFLAGS += -fsanitize=address
endif

# Directories
SRC_DIR = src
INC_DIR = include
BUILD_DIR = build
BIN_DIR = bin

# Sources
SOURCES = $(wildcard $(SRC_DIR)/*.cpp)
OBJECTS = $(patsubst $(SRC_DIR)/%.cpp,$(BUILD_DIR)/%.o,$(SOURCES))
HEADERS = $(wildcard $(INC_DIR)/*.h)

# Target executable
TARGET = $(BIN_DIR)/mixnet_demo

# ============================================================================
# Rules
# ============================================================================

.PHONY: all clean run release debug help

all: $(TARGET)

# Create directories
$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BIN_DIR):
	mkdir -p $(BIN_DIR)

# Link
$(TARGET): $(OBJECTS) | $(BIN_DIR)
	$(CXX) $(OBJECTS) -o $@ $(LDFLAGS)
	@echo ""
	@echo "╔════════════════════════════════════════════════════════╗"
	@echo "║     Build completed successfully!                      ║"
	@echo "║     Executable: $(TARGET)"
	@echo "╚════════════════════════════════════════════════════════╝"

# Compile
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp $(HEADERS) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -I$(INC_DIR) -c $< -o $@

# Clean
clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR)
	@echo "✓ Clean completed"

# Run
run: $(TARGET)
	./$(TARGET)

# Release build
release:
	$(MAKE) BUILD_TYPE=Release all

# Debug build
debug:
	$(MAKE) BUILD_TYPE=Debug all

# Windows executable (cross-compile from Linux)
windows:
	CXX=x86_64-w64-mingw32-g++ \
	LDFLAGS="-static -pthread" \
	$(MAKE) BUILD_TYPE=Release all
	@echo "✓ Windows executable generated: $(TARGET).exe"

# Install (Linux)
install: $(TARGET)
	cp $(TARGET) /usr/local/bin/mixnet_demo
	@echo "✓ Installed to /usr/local/bin/mixnet_demo"

# Uninstall
uninstall:
	rm -f /usr/local/bin/mixnet_demo
	@echo "✓ Uninstalled"

# Help
help:
	@echo ""
	@echo "╔════════════════════════════════════════════════════════╗"
	@echo "║     Advanced Mixnet - Makefile Help                    ║"
	@echo "╠════════════════════════════════════════════════════════╣"
	@echo "║ make            - Build (default: Release)             ║"
	@echo "║ make release    - Build with optimizations             ║"
	@echo "║ make debug      - Build with debug symbols             ║"
	@echo "║ make run        - Build and run                        ║"
	@echo "║ make clean      - Remove build files                   ║"
	@echo "║ make windows    - Cross-compile for Windows            ║"
	@echo "║ make install    - Install to /usr/local/bin            ║"
	@echo "║ make help       - Show this help                       ║"
	@echo "╚════════════════════════════════════════════════════════╝"
	@echo ""
