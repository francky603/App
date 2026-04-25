# CMakeLists.txt for Adaptive Mixnet with Polymorphic Encryption
cmake_minimum_required(VERSION 3.10)
project(AdaptiveMixnet VERSION 1.0.0 LANGUAGES CXX)

# Set C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compiler options
if(MSVC)
    add_compile_options(/W4 /O2)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -O2)
endif()

# Find threads package (required for std::thread)
find_package(Threads REQUIRED)

# Source files
set(SOURCES
    src/polymorphic_encryption.cpp
    src/mix_node.cpp
    src/adaptive_mixnet.cpp
)

# Header files
set(HEADERS
    include/polymorphic_encryption.h
    include/mix_node.h
    include/adaptive_mixnet.h
)

# Create executable
add_executable(${PROJECT_NAME} src/main.cpp ${SOURCES} ${HEADERS})

# Include directories
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_SOURCE_DIR}/include)

# Link libraries
target_link_libraries(${PROJECT_NAME} PRIVATE Threads::Threads)

# Installation rules
install(TARGETS ${PROJECT_NAME} DESTINATION bin)

# Optional: Create a library version
add_library(${PROJECT_NAME}_lib SHARED ${SOURCES} ${HEADERS})
target_include_directories(${PROJECT_NAME}_lib PUBLIC ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(${PROJECT_NAME}_lib PRIVATE Threads::Threads)
set_target_properties(${PROJECT_NAME}_lib PROPERTIES OUTPUT_NAME "adaptive_mixnet")

# Print configuration summary
message(STATUS "")
message(STATUS "Adaptive Mixnet Configuration Summary:")
message(STATUS "  Version: ${PROJECT_VERSION}")
message(STATUS "  C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "  Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "  Install Prefix: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")
