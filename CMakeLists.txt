cmake_minimum_required(VERSION 3.10)
project(SecureComm)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Find Threads
find_package(Threads REQUIRED)

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

# Add server executable
add_executable(server
    server/server.cpp
)

target_include_directories(server PRIVATE include)
target_link_libraries(server
    crypto_lib
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

# Add client executable
add_executable(client
    client/client.cpp
)

target_include_directories(client PRIVATE include)
target_link_libraries(client
    crypto_lib
    OpenSSL::SSL
    OpenSSL::Crypto
    Threads::Threads
)

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

# Drives three real clients through pipes. Needs bash; skipped where absent.
find_program(BASH_PROGRAM bash)
if(BASH_PROGRAM)
    add_test(NAME chat_integration
             COMMAND ${BASH_PROGRAM} ${CMAKE_SOURCE_DIR}/tests/integration_chat.sh
                     $<TARGET_FILE_DIR:server>)
    set_tests_properties(chat_integration PROPERTIES TIMEOUT 180)
endif()

# Set compiler flags and platform-specific settings
if(MSVC)
    target_compile_options(server PRIVATE /W4)
    target_compile_options(client PRIVATE /W4)
    target_compile_options(crypto_lib PRIVATE /W4)
else()
    target_compile_options(server PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(client PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(crypto_lib PRIVATE -Wall -Wextra -Wpedantic)
endif()

if(WIN32)
    # Windows socket library, needed by MSVC and MinGW alike
    target_link_libraries(server ws2_32)
    target_link_libraries(client ws2_32)

    # Copy the OpenSSL runtime DLLs next to each program, so they run (and ctest
    # passes) on a machine where OpenSSL's bin folder is not on PATH.
    get_filename_component(OPENSSL_INSTALL_DIR "${OPENSSL_INCLUDE_DIR}" DIRECTORY)
    file(GLOB OPENSSL_RUNTIME_DLLS
        "${OPENSSL_INSTALL_DIR}/bin/libcrypto*.dll"
        "${OPENSSL_INSTALL_DIR}/bin/libssl*.dll")
    if(OPENSSL_RUNTIME_DLLS)
        foreach(exe server client test_dh test_aes_gcm test_chat_envelope test_directional_keys)
            add_custom_command(TARGET ${exe} POST_BUILD
                COMMAND ${CMAKE_COMMAND} -E copy_if_different ${OPENSSL_RUNTIME_DLLS} $<TARGET_FILE_DIR:${exe}>)
        endforeach()
    endif()
endif()
