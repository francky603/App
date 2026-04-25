cmake_minimum_required(VERSION 3.15)
project(AdvancedMixnet VERSION 1.0.0 LANGUAGES CXX)

# ============================================================================
# Configuration du projet
# ============================================================================

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Options de compilation
option(BUILD_SHARED_LIBS "Build shared libraries" OFF)
option(ENABLE_TESTS "Enable tests" ON)
option(ENABLE_OPTIMIZATIONS "Enable optimizations for Release" ON)

# ============================================================================
# Flags de compilation spécifiques à la plateforme
# ============================================================================

if(MSVC)
    # Windows MSVC
    add_compile_options(/W4 /WX-)
    add_compile_options(/permissive-)
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        add_compile_options(/O2)
    endif()
else()
    # GCC/Clang
    add_compile_options(-Wall -Wextra -Wpedantic)
    add_compile_options(-fstack-protector-strong)
    
    if(CMAKE_BUILD_TYPE STREQUAL "Release")
        if(ENABLE_OPTIMIZATIONS)
            add_compile_options(-O3 -march=native)
        endif()
    else()
        add_compile_options(-g -fsanitize=address)
        add_link_options(-fsanitize=address)
    endif()
endif()

# ============================================================================
# Sources du projet
# ============================================================================

set(HEADERS
    include/crypto_types.h
    include/crypto_suite.h
    include/crypto_utils.h
    include/blockchain.h
    include/mix_session.h
)

set(SOURCES
    src/crypto_types.cpp
    src/crypto_suite.cpp
    src/crypto_utils.cpp
    src/blockchain.cpp
    src/mix_session.cpp
)

set(MAIN_SOURCE src/main.cpp)

# ============================================================================
# Bibliothèque principale
# ============================================================================

add_library(mixnet_lib STATIC ${SOURCES} ${HEADERS})
target_include_directories(mixnet_lib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)

# Threads
find_package(Threads REQUIRED)
target_link_libraries(mixnet_lib PUBLIC Threads::Threads)

# ============================================================================
# Exécutable principal
# ============================================================================

add_executable(mixnet_demo ${MAIN_SOURCE})
target_link_libraries(mixnet_demo PRIVATE mixnet_lib)

# ============================================================================
# Installation
# ============================================================================

install(TARGETS mixnet_demo DESTINATION bin)
install(DIRECTORY include/ DESTINATION include)

# ============================================================================
# Configuration pour Windows (génération .exe)
# ============================================================================

if(WIN32)
    set_target_properties(mixnet_demo PROPERTIES
        WIN32_EXECUTABLE TRUE
        OUTPUT_NAME "mixnet_demo"
    )
else()
    set_target_properties(mixnet_demo PROPERTIES
        OUTPUT_NAME "mixnet_demo"
    )
endif()

# ============================================================================
# Messages de configuration
# ============================================================================

message(STATUS "")
message(STATUS "╔════════════════════════════════════════════════════════╗")
message(STATUS "║     Advanced Mixnet - Configuration CMake              ║")
message(STATUS "╠════════════════════════════════════════════════════════╣")
message(STATUS "║ Version: ${PROJECT_VERSION}")
message(STATUS "║ C++ Standard: ${CMAKE_CXX_STANDARD}")
message(STATUS "║ Build Type: ${CMAKE_BUILD_TYPE}")
message(STATUS "║ Platform: ${CMAKE_SYSTEM_NAME}")
message(STATUS "╚════════════════════════════════════════════════════════╝")
message(STATUS "")
