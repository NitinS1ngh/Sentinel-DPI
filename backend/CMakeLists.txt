cmake_minimum_required(VERSION 3.16)
project(backend)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(Threads REQUIRED)
find_package(SQLite3 REQUIRED)

add_executable(sentineldpi
  src/main.cpp
  src/CaptureEngine.cpp
  src/Database.cpp
  src/DNSAnalyzer.cpp
  src/PolicyEngine.cpp
  src/AppConfig.cpp
  src/FirewallBackend.cpp
  src/ThreatIntel.cpp
  src/SecurityIntel.cpp
  src/ThreatFeedUpdater.cpp
  src/BlockingEngine.cpp
  src/EventBroadcaster.cpp
  src/ApiServer.cpp
)

target_include_directories(sentineldpi PRIVATE ${SQLite3_INCLUDE_DIRS} src)
target_link_libraries(sentineldpi PRIVATE ${SQLite3_LIBRARIES} Threads::Threads)

if(USE_PCAPPP)
  message(STATUS "PcapPlusPlus integration enabled - user must configure include/link paths")
  target_compile_definitions(sentineldpi PRIVATE USE_PCAPPP)
  # If user didn't pass include/lib paths, try common Homebrew locations on macOS (Apple Silicon)
  if(NOT DEFINED PCAPP_INCLUDE_DIR AND EXISTS "/opt/homebrew/include/pcapplusplus")
    set(PCAPP_INCLUDE_DIR "/opt/homebrew/include/pcapplusplus")
  endif()
  if(NOT DEFINED PCAPP_LIBS)
    if (EXISTS "/opt/homebrew/lib/libPcapPlusPlus.a")
      set(PCAPP_LIBS "/opt/homebrew/lib/libPcapPlusPlus.a")
    elseif (EXISTS "/opt/homebrew/lib/libPcapPlusPlus.dylib")
      set(PCAPP_LIBS "/opt/homebrew/lib/libPcapPlusPlus.dylib")
    endif()
  endif()

  # If still not set, try to auto-find PcapPlusPlus library in common locations
  if(NOT DEFINED PCAPP_LIBS)
    find_library(PCAPP_LIB NAMES PcapPlusPlus libPcapPlusPlus PATHS /opt/homebrew/lib /usr/local/lib /usr/lib)
    if(PCAPP_LIB)
      set(PCAPP_LIBS ${PCAPP_LIB})
      message(STATUS "Auto-found PcapPlusPlus lib: ${PCAPP_LIBS}")
    endif()
  endif()

  if(DEFINED PCAPP_INCLUDE_DIR)
    target_include_directories(sentineldpi PRIVATE ${PCAPP_INCLUDE_DIR})
  endif()
  if(DEFINED PCAPP_LIBS)
    # If PCAPP_LIBS is a full path to a library file, link it directly.
    target_link_libraries(sentineldpi PRIVATE ${PCAPP_LIBS})
    message(STATUS "Using PcapPlusPlus lib: ${PCAPP_LIBS}")
  else()
    message(WARNING "PcapPlusPlus library not set; linking may fail")
  endif()
  # If user provided a library directory, try linking by name from that directory
  if(NOT DEFINED PCAPP_LIBS AND DEFINED PCAPP_LIB_DIR)
    message(STATUS "Using PCAPP_LIB_DIR: ${PCAPP_LIB_DIR}, linking -lPcapPlusPlus from that directory")
    link_directories(${PCAPP_LIB_DIR})
    target_link_libraries(sentineldpi PRIVATE PcapPlusPlus)
  endif()
  if(DEFINED PCAPP_INCLUDE_DIR)
    message(STATUS "Using PcapPlusPlus include: ${PCAPP_INCLUDE_DIR}")
  endif()

  # Try to find libpcap and link it; PcapPlusPlus depends on libpcap
  find_library(PCAP_LIB pcap)
  if(PCAP_LIB)
    message(STATUS "Found libpcap: ${PCAP_LIB}")
    target_link_libraries(sentineldpi PRIVATE ${PCAP_LIB})
  else()
    message(WARNING "libpcap not found. Install libpcap or set link paths manually.")
  endif()
  
  if(APPLE)
    target_link_libraries(
        sentineldpi PRIVATE
        "-framework CoreFoundation"
        "-framework SystemConfiguration"
    )
endif()
endif()
