set(CMAKE_CURRENT_SOURCE_DIR src/mitm)
set(cwd ${CMAKE_CURRENT_SOURCE_DIR})

set(
    MITM_HEADERS

    ${cwd}/Adapter.h
    ${cwd}/AdapterList.h
    ${cwd}/Packets.h
    ${cwd}/NetUtils.h

    PARENT_SCOPE
)

set(
    MITM_SOURCES

    ${cwd}/Adapter.cpp
    ${cwd}/AdapterList.cpp
    ${cwd}/Packets.cpp
    ${cwd}/NetUtils.cpp

    PARENT_SCOPE
)
