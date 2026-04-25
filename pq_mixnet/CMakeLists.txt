cmake_minimum_required(VERSION 3.16)
project(PQ_Mixnet VERSION 1.0 LANGUAGES CXX)

# Standard C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Options de compilation
if(MSVC)
    add_compile_options(/W4 /O2 /std:c++17)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS -D_WIN32_WINNT=0x0A00)
else()
    add_compile_options(-Wall -Wextra -O2 -pthread)
endif()

# Inclure le dossier include
include_directories(${CMAKE_SOURCE_DIR}/include)

# Sources communes
set(COMMON_SOURCES
    src/pqc_core.cpp
    src/polymorphic_engine.cpp
    src/mixnet_node.cpp
    src/network_protocol.cpp
)

# Client executable
add_executable(pq_mixnet_client
    src/client.cpp
    ${COMMON_SOURCES}
)

# Server executable
add_executable(pq_mixnet_server
    src/server.cpp
    ${COMMON_SOURCES}
)

# Installation
install(TARGETS pq_mixnet_client pq_mixnet_server
    RUNTIME DESTINATION bin
)

# Message de configuration
message(STATUS "PQ Mixnet - Post-Quantum Polymorphic Mixnet")
message(STATUS "Build type: ${CMAKE_BUILD_TYPE}")
message(STATUS "Compiler: ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
