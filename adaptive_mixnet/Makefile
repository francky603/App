# Makefile for Adaptive Mixnet with Polymorphic Encryption

CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -Wpedantic -O2
LDFLAGS = -pthread

# Directories
SRC_DIR = src
INC_DIR = include
BUILD_DIR = build
BIN_DIR = bin

# Source files
SOURCES = $(SRC_DIR)/polymorphic_encryption.cpp \
          $(SRC_DIR)/mix_node.cpp \
          $(SRC_DIR)/adaptive_mixnet.cpp \
          $(SRC_DIR)/main.cpp

# Object files
OBJECTS = $(SOURCES:$(SRC_DIR)/%.cpp=$(BUILD_DIR)/%.o)

# Target executable
TARGET = $(BIN_DIR)/adaptive_mixnet

# Include flags
INCLUDES = -I$(INC_DIR)

# Default target
all: directories $(TARGET)

# Create necessary directories
directories:
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(BIN_DIR)

# Link the executable
$(TARGET): $(OBJECTS)
	$(CXX) $(OBJECTS) -o $@ $(LDFLAGS)

# Compile source files
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# Run the program
run: $(TARGET)
	./$(TARGET)

# Debug build
debug: CXXFLAGS += -g -DDEBUG
debug: clean all

# Release build
release: CXXFLAGS += -O3 -DNDEBUG
release: clean all

# Clean build artifacts
clean:
	rm -rf $(BUILD_DIR)
	rm -rf $(BIN_DIR)

# Install (requires sudo)
install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

# Uninstall
uninstall:
	rm -f /usr/local/bin/adaptive_mixnet

# Help target
help:
	@echo "Adaptive Mixnet Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all      - Build the project (default)"
	@echo "  run      - Build and run the program"
	@echo "  debug    - Build with debug symbols"
	@echo "  release  - Build with optimizations"
	@echo "  clean    - Remove build artifacts"
	@echo "  install  - Install to /usr/local/bin"
	@echo "  uninstall- Remove from /usr/local/bin"
	@echo "  help     - Show this help message"

.PHONY: all directories run debug release clean install uninstall help
