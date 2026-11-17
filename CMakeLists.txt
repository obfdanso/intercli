cmake_minimum_required(VERSION 3.21)
project(SecureComm VERSION 1.0.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Find Threads
find_package(Threads REQUIRED)

# Qt 6 is optional: without it everything except the desktop app still builds.
find_package(Qt6 6.5 COMPONENTS Quick QuickControls2 Sql Test Network QUIET)

# Include directories
include_directories(include)

# Add crypto library
add_library(crypto_lib
    crypto/crypto_utils.cpp
)

target_include_directories(crypto_lib PUBLIC include)
target_link_libraries(crypto_lib
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

# Chat server library shared by server.exe and the desktop app (hosting)
add_library(intercli_server_core STATIC
    server/core/secure_server.cpp
)
target_include_directories(intercli_server_core PUBLIC include server/core)
target_link_libraries(intercli_server_core PUBLIC
    crypto_lib
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)
if(WIN32)
    target_link_libraries(intercli_server_core PUBLIC ws2_32)
endif()

# Add server executable
add_executable(server
    server/server.cpp
)
target_link_libraries(server intercli_server_core)
if(WIN32)
    target_link_libraries(server crypt32)
endif()

# Client protocol library shared by the terminal client and the desktop app
add_library(intercli_client_core STATIC
    client/core/chat_client.cpp
    client/core/key_store.cpp
)

target_include_directories(intercli_client_core PUBLIC include client/core)
target_link_libraries(intercli_client_core PUBLIC
    crypto_lib
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)
if(WIN32)
    target_link_libraries(intercli_client_core PUBLIC ws2_32)
endif()

# Add client executable
add_executable(client
    client/client.cpp
)

target_link_libraries(client intercli_client_core)

# Add DH regression test
enable_testing()

add_executable(test_dh
    tests/test_dh.cpp
)

target_include_directories(test_dh PRIVATE include crypto)
target_link_libraries(test_dh
    crypto_lib
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

add_test(NAME dh_key_exchange COMMAND test_dh)

add_executable(test_aes_gcm
    tests/test_aes_gcm.cpp
)

target_include_directories(test_aes_gcm PRIVATE include crypto)
target_link_libraries(test_aes_gcm
    crypto_lib
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

add_test(NAME aes_gcm COMMAND test_aes_gcm)

add_executable(test_chat_envelope
    tests/test_chat_envelope.cpp
)

target_include_directories(test_chat_envelope PRIVATE include crypto)
target_link_libraries(test_chat_envelope
    crypto_lib
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

add_test(NAME chat_envelope COMMAND test_chat_envelope)

add_executable(test_directional_keys
    tests/test_directional_keys.cpp
)

target_include_directories(test_directional_keys PRIVATE include crypto)
target_link_libraries(test_directional_keys
    crypto_lib
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

add_test(NAME directional_keys COMMAND test_directional_keys)

add_executable(test_identity
    tests/test_identity.cpp
)
target_include_directories(test_identity PRIVATE include crypto)
target_link_libraries(test_identity crypto_lib)
add_test(NAME identity COMMAND test_identity)

add_executable(test_server_core
    tests/test_server_core.cpp
)
target_link_libraries(test_server_core intercli_server_core intercli_client_core)
add_test(NAME server_core COMMAND test_server_core)

add_executable(test_roster
    tests/test_roster.cpp
)
target_link_libraries(test_roster intercli_client_core)
add_test(NAME roster COMMAND test_roster)

add_executable(test_key_store
    tests/test_key_store.cpp
)
target_include_directories(test_key_store PRIVATE crypto)
target_link_libraries(test_key_store intercli_client_core)
add_test(NAME key_store COMMAND test_key_store)

add_executable(test_chat_client
    tests/test_chat_client.cpp
)
target_link_libraries(test_chat_client intercli_client_core)

# Drives three real clients through pipes. Needs bash; skipped where absent.
find_program(BASH_PROGRAM bash)
if(BASH_PROGRAM)
    add_test(NAME chat_integration
             COMMAND ${BASH_PROGRAM} ${CMAKE_SOURCE_DIR}/tests/integration_chat.sh
                     $<TARGET_FILE_DIR:server>)
    set_tests_properties(chat_integration PROPERTIES TIMEOUT 180 RESOURCE_LOCK port8080)

    add_test(NAME chat_client
             COMMAND ${BASH_PROGRAM} ${CMAKE_SOURCE_DIR}/tests/run_with_server.sh
                     $<TARGET_FILE:server> $<TARGET_FILE:test_chat_client>)
    set_tests_properties(chat_client PROPERTIES TIMEOUT 120 RESOURCE_LOCK port8080)
endif()

# Set compiler flags and platform-specific settings
if(MSVC)
    target_compile_options(server PRIVATE /W4)
    target_compile_options(client PRIVATE /W4)
    target_compile_options(crypto_lib PRIVATE /W4)
    target_compile_options(intercli_client_core PRIVATE /W4)
    target_compile_options(intercli_server_core PRIVATE /W4)
else()
    target_compile_options(server PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(client PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(crypto_lib PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(intercli_client_core PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(intercli_server_core PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(WIN32)
    # Windows socket library, needed by MSVC and MinGW alike

    # Copy the OpenSSL runtime DLLs next to each program, so they run (and ctest
    # passes) on a machine where OpenSSL's bin folder is not on PATH.
    get_filename_component(OPENSSL_INSTALL_DIR "${OPENSSL_INCLUDE_DIR}" DIRECTORY)
    file(GLOB OPENSSL_RUNTIME_DLLS
        "${OPENSSL_INSTALL_DIR}/bin/libcrypto*.dll"
        "${OPENSSL_INSTALL_DIR}/bin/libssl*.dll")
    if(OPENSSL_RUNTIME_DLLS)
        foreach(exe server client test_dh test_aes_gcm test_chat_envelope test_directional_keys test_roster test_chat_client test_identity test_server_core test_key_store)
            add_custom_command(TARGET ${exe} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different ${OPENSSL_RUNTIME_DLLS} $<TARGET_FILE_DIR:${exe}>)
        endforeach()
    endif()
endif()

# What goes into an installed copy or a package: the programs, the libraries
# they need to start, and the readme. Everything sits in one folder on
# Windows; elsewhere the programs go in bin.
if(WIN32)
    set(INTERCLI_BIN_DIR ".")
else()
    set(INTERCLI_BIN_DIR "bin")
endif()
install(TARGETS server client RUNTIME DESTINATION ${INTERCLI_BIN_DIR})
install(FILES README.md DESTINATION .)
if(WIN32 AND OPENSSL_RUNTIME_DLLS)
    install(FILES ${OPENSSL_RUNTIME_DLLS} DESTINATION ${INTERCLI_BIN_DIR})
endif()
# The compiler's own runtime DLLs, so nothing else has to be installed first.
set(CMAKE_INSTALL_SYSTEM_RUNTIME_DESTINATION ${INTERCLI_BIN_DIR})
include(InstallRequiredSystemLibraries)

# Desktop app, last so it can reuse OPENSSL_RUNTIME_DLLS from above.
if(Qt6_FOUND)
    add_subdirectory(gui)
else()
    message(STATUS "Qt6 not found: skipping the desktop app")
endif()

# Packages: "cpack -C Release" in the build folder makes a zip on Windows (and
# an installer too if NSIS is installed), a .tar.gz elsewhere.
set(CPACK_PACKAGE_NAME "intercli")
set(CPACK_PACKAGE_VENDOR "Danso")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Encrypted chat for people on the same network")
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION})
set(CPACK_PACKAGE_INSTALL_DIRECTORY "intercli")
set(CPACK_PACKAGE_FILE_NAME "intercli-${PROJECT_VERSION}-${CMAKE_SYSTEM_NAME}")
set(CPACK_RESOURCE_FILE_README "${CMAKE_SOURCE_DIR}/README.md")
if(WIN32)
    set(CPACK_GENERATOR "ZIP")
    find_program(MAKENSIS_EXECUTABLE makensis
                 PATHS "$ENV{ProgramFiles\(x86\)}/NSIS" "$ENV{ProgramFiles}/NSIS")
    if(MAKENSIS_EXECUTABLE)
        list(APPEND CPACK_GENERATOR "NSIS")
        set(CPACK_NSIS_DISPLAY_NAME "intercli")
        set(CPACK_NSIS_PACKAGE_NAME "intercli")
        set(CPACK_NSIS_ENABLE_UNINSTALL_BEFORE_INSTALL ON)
        if(TARGET intercli_gui)
            set(CPACK_NSIS_MENU_LINKS "intercli.exe" "intercli")
            set(CPACK_NSIS_INSTALLED_ICON_NAME "intercli.exe")
        endif()
    endif()
else()
    set(CPACK_GENERATOR "TGZ")
endif()
include(CPack)
