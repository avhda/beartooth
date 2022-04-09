set(CMAKE_CURRENT_SOURCE_DIR src/ui)
set(cwd ${CMAKE_CURRENT_SOURCE_DIR})

set(
    UI_HEADERS

    ${cwd}/Client.h
    ${cwd}/PacketRenderers.h
    ${cwd}/ConfigLoader.h

    PARENT_SCOPE
)

set(
    UI_SOURCES

    ${cwd}/Client.cpp
    ${cwd}/PacketRenderers.cpp
    ${cwd}/ConfigLoader.cpp

    PARENT_SCOPE
)
