cmake_minimum_required(VERSION 3.16)
project(SentinelDPI LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(USE_PCAPPP "Enable PcapPlusPlus integration" OFF)
option(USE_CROW "Enable Crow HTTP server" OFF)

add_subdirectory(backend)
