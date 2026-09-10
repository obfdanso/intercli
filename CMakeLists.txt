cmake_minimum_required(VERSION 3.10)
project(SecureComm)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Find Threads
find_package(Threads REQUIRED)

# Find Qt6 (or Qt5 if Qt6 is not available) - Optional
find_package(Qt6 COMPONENTS Core Widgets Network QUIET)
if(NOT Qt6_FOUND)
    find_package(Qt5 COMPONENTS Core Widgets Network QUIET)
endif()

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

# The GUI clients are off by default: client/gui_client_win.cpp was written against an
# older protocol API (HandshakeMessage::version, client_public_key_size,
# ForwardSecrecyType::DH_2048, CryptoManager::encrypt_message) that no longer exists in
# include/common.h, so it does not compile. Turn this on once it has been ported.
option(BUILD_GUI_CLIENT "Build the GUI client (currently out of sync with the protocol headers)" OFF)

# Add GUI client executable (only if Qt is available)
if(BUILD_GUI_CLIENT)
if(Qt6_FOUND OR Qt5_FOUND)
    add_executable(gui_client
        client/gui_client.cpp
        client/gui_client.h
        client/gui_client.ui
    )

    target_include_directories(gui_client PRIVATE include)
    target_link_libraries(gui_client
        crypto_lib
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
        Qt::Core
        Qt::Widgets
        Qt::Network
    )
else()
    # Create a Windows API-based GUI client instead
    add_executable(gui_client
        client/gui_client_win.cpp
    )

    target_include_directories(gui_client PRIVATE include)
    target_link_libraries(gui_client
        crypto_lib
        OpenSSL::SSL
        OpenSSL::Crypto
        Threads::Threads
    )
endif()
endif()

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

# Set compiler flags and platform-specific settings
if(MSVC)
    target_compile_options(server PRIVATE /W4)
    target_compile_options(client PRIVATE /W4)
    target_compile_options(crypto_lib PRIVATE /W4)

    # Add Windows socket library
    target_link_libraries(server ws2_32)
    target_link_libraries(client ws2_32)

    if(BUILD_GUI_CLIENT)
        target_compile_options(gui_client PRIVATE /W4)
        target_link_libraries(gui_client ws2_32)
    endif()
else()
    target_compile_options(server PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(client PRIVATE -Wall -Wextra -Wpedantic)
    target_compile_options(crypto_lib PRIVATE -Wall -Wextra -Wpedantic)

    if(BUILD_GUI_CLIENT)
        target_compile_options(gui_client PRIVATE -Wall -Wextra -Wpedantic)
    endif()
endif() 