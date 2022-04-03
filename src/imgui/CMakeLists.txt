set(CMAKE_CURRENT_SOURCE_DIR src/imgui)
set(cwd ${CMAKE_CURRENT_SOURCE_DIR})

set(
    IMGUI_HEADERS

    ${cwd}/imgui_impl_dx11.h
    ${cwd}/imgui_impl_win32.h
    ${cwd}/imgui.h
    ${cwd}/imconfig.h
    ${cwd}/imgui_internal.h
    ${cwd}/imstb_rectpack.h
    ${cwd}/imstb_textedit.h
    ${cwd}/imstb_truetype.h

    PARENT_SCOPE
)

set(
    IMGUI_SOURCES

    ${cwd}/imgui_impl_dx11.cpp
    ${cwd}/imgui_impl_win32.cpp
    ${cwd}/imgui.cpp
    ${cwd}/imgui_draw.cpp
    ${cwd}/imgui_tables.cpp
    ${cwd}/imgui_widgets.cpp

    PARENT_SCOPE
)
