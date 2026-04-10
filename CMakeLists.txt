cmake_minimum_required(VERSION 3.20)
project(cecore VERSION 0.1.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# ── Options ──
option(CECORE_BUILD_TESTS "Build test programs" ON)

# ── Find Capstone + Keystone ──
find_library(CAPSTONE_LIB capstone REQUIRED)
find_path(CAPSTONE_INCLUDE capstone/capstone.h REQUIRED)
find_library(KEYSTONE_LIB keystone REQUIRED)
find_path(KEYSTONE_INCLUDE keystone/keystone.h REQUIRED)

# ── Find Lua 5.3 ──
set(LUA_DIR "${CMAKE_SOURCE_DIR}/../Cheat Engine/lua53/lua53/src")

# ── ceserver C library (existing code, available for future use) ──
set(CESERVER_DIR "${CMAKE_SOURCE_DIR}/../Cheat Engine/ceserver")

add_library(ceserver_c STATIC
    ${CESERVER_DIR}/api.c
    ${CESERVER_DIR}/threads.c
    ${CESERVER_DIR}/context.c
    ${CESERVER_DIR}/symbols.c
    ${CESERVER_DIR}/extensionfunctions.c
    ${CESERVER_DIR}/extensionloader.c
    ${CESERVER_DIR}/porthelp.c
    ${CESERVER_DIR}/native-api.c
    ${CESERVER_DIR}/options.c
)
target_compile_definitions(ceserver_c PRIVATE CECORE_LIBRARY_MODE=1)
target_include_directories(ceserver_c PUBLIC ${CESERVER_DIR})
target_compile_options(ceserver_c PRIVATE
    -fPIC
    -Wno-missing-field-initializers
    -Wno-unused-parameter
    -Wno-sign-compare
    -Wno-implicit-function-declaration
    -Doff64_t=__off64_t
)
target_link_libraries(ceserver_c PUBLIC z dl pthread)

# ── libcecore C++ library ──
add_library(cecore SHARED
    core/types.cpp
    core/autoasm.cpp
    core/expression.cpp
    core/ct_file.cpp
    core/trainer.cpp
    analysis/code_analysis.cpp
    platform/linux/linux_process.cpp
    platform/linux/ptrace_wrapper.cpp
    platform/linux/injector.cpp
    platform/linux/ceserver_stubs.c
    arch/disassembler.cpp
    arch/assembler.cpp
    symbols/elf_symbols.cpp
    debug/breakpoint_manager.cpp
    debug/code_finder.cpp
    debug/tracer.cpp
    scanner/memory_scanner.cpp
    scanner/pointer_scanner.cpp
    scripting/lua_engine.cpp
    scripting/lua_bindings.cpp
    plugins/plugin_loader.cpp
)
target_include_directories(cecore PUBLIC
    ${CMAKE_SOURCE_DIR}
    ${CAPSTONE_INCLUDE}
    ${KEYSTONE_INCLUDE}
    ${LUA_DIR}
)
target_link_libraries(cecore PRIVATE
    dl pthread ${CAPSTONE_LIB} ${KEYSTONE_LIB}
    ${LUA_DIR}/liblua.a m  # Static link Lua
)

# ── CLI tool ──
add_executable(cescan cli/main.cpp)
target_link_libraries(cescan PRIVATE cecore)

# ── Speedhack .so ──
add_library(speedhack SHARED plugins/speedhack.c)
target_link_libraries(speedhack PRIVATE dl rt)
set_target_properties(speedhack PROPERTIES PREFIX "lib")

# ── Qt6 GUI ──
find_package(Qt6 COMPONENTS Widgets)
if(Qt6_FOUND)
    set(CMAKE_AUTOMOC ON)
    qt_add_executable(cheatengine
        gui/resources.qrc
        gui/main.cpp
        gui/mainwindow.cpp
        gui/processlistdialog.cpp
        gui/memorybrowser.cpp
        gui/scripteditor.cpp
        gui/pointerscan_dialog.cpp
        gui/structuredissector.cpp
        gui/luaconsole.cpp
        gui/breakpointlist.cpp
        gui/codefinder.cpp
        gui/memoryregions.cpp
        gui/threadlist.cpp
        gui/settingsdialog.cpp
        scripting/lua_gui.cpp
    )
    target_include_directories(cheatengine PRIVATE ${LUA_DIR})
    target_link_libraries(cheatengine PRIVATE cecore Qt6::Widgets)
    message(STATUS "Qt6 found — building GUI")
else()
    message(STATUS "Qt6 not found — skipping GUI build")
endif()

# ── Test programs ──
if(CECORE_BUILD_TESTS)
    add_executable(cecore_test test/main.cpp)
    target_link_libraries(cecore_test PRIVATE cecore)

    add_executable(scan_test test/scan_test.cpp)
    target_link_libraries(scan_test PRIVATE cecore)
endif()
