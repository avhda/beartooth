cmake_minimum_required(VERSION 3.0)
set(CMAKE_CONFIGURATION_TYPES "Debug;Release")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_definitions(-DUNICODE -D_UNICODE -D_WINSOCK_DEPRECATED_NO_WARNINGS)

set(NPCAP_SDK_PATH "C:\\Program Files\\NpcapSDK")
set(NPCAP_INCLUDE_DIR ${NPCAP_SDK_PATH}\\Include)
set(NPCAP_LIBRARY_DIR ${NPCAP_SDK_PATH}\\Lib\\x64)

project(beartooth)
include_directories(src)

message("----------------------------------------------")
message("-- CMake       ${CMAKE_VERSION}")
message("-- Build       ${CMAKE_SYSTEM_NAME}")
message("-- Npcap SDK   ${NPCAP_SDK_PATH}")
message("----------------------------------------------")

set(TARGET_NAME ${PROJECT_NAME})

add_subdirectory(src/mitm)
add_subdirectory(src/imgui)
add_subdirectory(src/ui)

add_executable(
    ${TARGET_NAME}
    
    ${MITM_HEADERS}
    ${MITM_SOURCES}
    ${IMGUI_HEADERS}
    ${IMGUI_SOURCES}
    ${UI_HEADERS}
    ${UI_SOURCES}

    src/main.cpp
)

target_include_directories(${TARGET_NAME} PUBLIC ${NPCAP_INCLUDE_DIR})
target_link_directories(${TARGET_NAME} PUBLIC ${NPCAP_LIBRARY_DIR})
target_link_libraries(${TARGET_NAME} Packet.lib wpcap.lib Ws2_32.lib d3d11.lib)

add_custom_command(
    TARGET ${PROJECT_NAME} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
    ${CMAKE_SOURCE_DIR}/config $<TARGET_FILE_DIR:${PROJECT_NAME}>/config
)
