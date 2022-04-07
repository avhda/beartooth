set(CMAKE_CURRENT_SOURCE_DIR src/ui)
set(cwd ${CMAKE_CURRENT_SOURCE_DIR})

set(
    UI_HEADERS

    ${cwd}/Client.h
    ${cwd}/PacketFilters.h

    PARENT_SCOPE
)

set(
    UI_SOURCES

    ${cwd}/Client.cpp
    ${cwd}/PacketFilters.cpp

    PARENT_SCOPE
)
