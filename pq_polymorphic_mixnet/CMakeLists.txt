cmake_minimum_required(VERSION 3.16)
project(AdvancedPQMixnet VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Options de compilation optimisées
if(MSVC)
    add_compile_options(/O2 /W4 /DNOMINMAX)
    # Lien statique pour un exe portable sous Windows
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
else()
    add_compile_options(-O3 -Wall -Wextra -pthread)
endif()

find_package(Threads REQUIRED)

# Sources communes
set(COMMON_SOURCES
    src/crypto_pqc.cpp
    src/polymorphic_engine.cpp
    src/mixnet_node.cpp
    src/protocol.cpp
)

set(COMMON_INCLUDES include)

# --- Exécutable Serveur ---
add_executable(mixnet_server src/main_server.cpp ${COMMON_SOURCES})
target_include_directories(mixnet_server PRIVATE ${COMMON_INCLUDES})
target_link_libraries(mixnet_server PRIVATE Threads::Threads)

# --- Exécutable Client ---
add_executable(mixnet_client src/main_client.cpp ${COMMON_SOURCES})
target_include_directories(mixnet_client PRIVATE ${COMMON_INCLUDES})
target_link_libraries(mixnet_client PRIVATE Threads::Threads)

install(TARGETS mixnet_server mixnet_client DESTINATION bin)

message(STATUS "Configuration terminée. Générez avec: cmake -B build && cmake --build build")
message(STATUS "Cibles générées: mixnet_server, mixnet_client")
