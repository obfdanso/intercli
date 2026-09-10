#include "common.h"
#include "../crypto/crypto_utils.h"
// winsock2.h must precede windows.h, which would otherwise pull in the
// conflicting legacy winsock.h.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <commctrl.h>
#include <iostream>
#include <string>
#include <memory>
#include <vector>
#include <thread>
#include <mutex>
#include <chrono>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "comctl32.lib")

// Window handles
HWND hMainWindow = nullptr;
HWND hServerIpEdit = nullptr;
HWND hServerPortEdit = nullptr;
HWND hConnectButton = nullptr;
HWND hDisconnectButton = nullptr;
HWND hMessageDisplay = nullptr;
HWND hMessageInput = nullptr;
HWND hSendButton = nullptr;
HWND hKeyRotationButton = nullptr;
HWND hStatusLabel = nullptr;

// Client state
bool isConnected = false;
int clientSocket = -1;
std::unique_ptr<SecureComm::CryptoManager> cryptoManager;
std::unique_ptr<SecureComm::SessionManager> sessionManager;
std::unique_ptr<SecureComm::KeyManager> keyManager;
SecureComm::KeyPair clientKeypair;
SecureComm::SessionInfo currentSession;
std::vector<uint8_t> sessionKey;
uint32_t messageCounter = 0;
std::thread messageThread;
std::mutex clientMutex;
bool shouldRun = false;

// Window procedure
LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);

// Client functions
bool connectToServer(const std::string& serverIp, uint16_t port);
void disconnectFromServer();
bool sendMessage(const std::string& message);
bool performHandshake();
std::string receiveEncryptedMessage();
std::vector<uint8_t> receiveData();
bool sendData(const std::vector<uint8_t>& data);
void messageLoop();
void logMessage(const std::string& message, const std::string& type = "INFO");

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    // Initialize Common Controls
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
    icex.dwICC = ICC_WIN95_CLASSES;
    InitCommonControlsEx(&icex);

    // Initialize Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        MessageBox(nullptr, "WSAStartup failed", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    // Initialize crypto components
    cryptoManager = std::make_unique<SecureComm::CryptoManager>();
    sessionManager = std::make_unique<SecureComm::SessionManager>();
    keyManager = std::make_unique<SecureComm::KeyManager>();
    
    // Generate client's RSA key pair
    clientKeypair = cryptoManager->generate_rsa_keypair(2048);

    // Register window class
    const char* className = "SecureCommClient";
    WNDCLASSEX wc = {};
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = className;
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);
    wc.hIconSm = LoadIcon(nullptr, IDI_APPLICATION);

    if (!RegisterClassEx(&wc)) {
        MessageBox(nullptr, "Window registration failed", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    // Create main window
    hMainWindow = CreateWindowEx(
        0,
        className,
        "Secure Communication Client",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 800, 600,
        nullptr, nullptr, hInstance, nullptr
    );

    if (!hMainWindow) {
        MessageBox(nullptr, "Window creation failed", "Error", MB_OK | MB_ICONERROR);
        return 1;
    }

    // Create controls
    CreateWindow("STATIC", "Server IP:", WS_VISIBLE | WS_CHILD,
        10, 10, 80, 20, hMainWindow, nullptr, hInstance, nullptr);
    
    hServerIpEdit = CreateWindow("EDIT", "127.0.0.1", WS_VISIBLE | WS_CHILD | WS_BORDER,
        100, 10, 120, 20, hMainWindow, nullptr, hInstance, nullptr);

    CreateWindow("STATIC", "Port:", WS_VISIBLE | WS_CHILD,
        230, 10, 40, 20, hMainWindow, nullptr, hInstance, nullptr);
    
    hServerPortEdit = CreateWindow("EDIT", "8080", WS_VISIBLE | WS_CHILD | WS_BORDER,
        280, 10, 60, 20, hMainWindow, nullptr, hInstance, nullptr);

    hConnectButton = CreateWindow("BUTTON", "Connect", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        350, 10, 80, 20, hMainWindow, (HMENU)1, hInstance, nullptr);

    hDisconnectButton = CreateWindow("BUTTON", "Disconnect", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        440, 10, 80, 20, hMainWindow, (HMENU)2, hInstance, nullptr);
    EnableWindow(hDisconnectButton, FALSE);

    hStatusLabel = CreateWindow("STATIC", "Disconnected", WS_VISIBLE | WS_CHILD,
        530, 10, 200, 20, hMainWindow, nullptr, hInstance, nullptr);

    // Message display
    CreateWindow("STATIC", "Messages:", WS_VISIBLE | WS_CHILD,
        10, 40, 80, 20, hMainWindow, nullptr, hInstance, nullptr);

    hMessageDisplay = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER | ES_MULTILINE | ES_READONLY | WS_VSCROLL,
        10, 60, 760, 400, hMainWindow, nullptr, hInstance, nullptr);

    // Message input
    hMessageInput = CreateWindow("EDIT", "", WS_VISIBLE | WS_CHILD | WS_BORDER,
        10, 470, 600, 20, hMainWindow, nullptr, hInstance, nullptr);
    EnableWindow(hMessageInput, FALSE);

    hSendButton = CreateWindow("BUTTON", "Send", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        620, 470, 60, 20, hMainWindow, (HMENU)3, hInstance, nullptr);
    EnableWindow(hSendButton, FALSE);

    hKeyRotationButton = CreateWindow("BUTTON", "Rotate Keys", WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        690, 470, 80, 20, hMainWindow, (HMENU)4, hInstance, nullptr);
    EnableWindow(hKeyRotationButton, FALSE);

    // Show window
    ShowWindow(hMainWindow, nCmdShow);
    UpdateWindow(hMainWindow);

    logMessage("GUI Client initialized. Ready to connect to server.", "INFO");

    // Message loop
    MSG msg = {};
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // Cleanup
    if (isConnected) {
        disconnectFromServer();
    }
    WSACleanup();

    return 0;
}

LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg) {
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case 1: // Connect button
            if (!isConnected) {
                char serverIp[256];
                char serverPort[32];
                GetWindowText(hServerIpEdit, serverIp, sizeof(serverIp));
                GetWindowText(hServerPortEdit, serverPort, sizeof(serverPort));
                
                uint16_t port = static_cast<uint16_t>(atoi(serverPort));
                if (connectToServer(serverIp, port)) {
                    isConnected = true;
                    EnableWindow(hConnectButton, FALSE);
                    EnableWindow(hDisconnectButton, TRUE);
                    EnableWindow(hMessageInput, TRUE);
                    EnableWindow(hSendButton, TRUE);
                    EnableWindow(hKeyRotationButton, TRUE);
                    SetWindowText(hStatusLabel, "Connected");
                    logMessage("Connected to server", "SUCCESS");
                } else {
                    MessageBox(hwnd, "Failed to connect to server", "Error", MB_OK | MB_ICONERROR);
                }
            }
            break;

        case 2: // Disconnect button
            if (isConnected) {
                disconnectFromServer();
                isConnected = false;
                EnableWindow(hConnectButton, TRUE);
                EnableWindow(hDisconnectButton, FALSE);
                EnableWindow(hMessageInput, FALSE);
                EnableWindow(hSendButton, FALSE);
                EnableWindow(hKeyRotationButton, FALSE);
                SetWindowText(hStatusLabel, "Disconnected");
                logMessage("Disconnected from server", "WARNING");
            }
            break;

        case 3: // Send button
            if (isConnected) {
                char message[1024];
                GetWindowText(hMessageInput, message, sizeof(message));
                if (strlen(message) > 0) {
                    if (sendMessage(message)) {
                        logMessage("Sent: " + std::string(message), "SENT");
                        SetWindowText(hMessageInput, "");
                    } else {
                        logMessage("Failed to send message", "ERROR");
                    }
                }
            }
            break;

        case 4: // Key rotation button
            if (isConnected) {
                logMessage("Key rotation requested", "INFO");
                // Implement key rotation here
            }
            break;
        }
        break;

    case WM_DESTROY:
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProc(hwnd, uMsg, wParam, lParam);
    }
    return 0;
}

bool connectToServer(const std::string& serverIp, uint16_t port)
{
    std::lock_guard<std::mutex> lock(clientMutex);

    clientSocket = static_cast<int>(socket(AF_INET, SOCK_STREAM, 0));
    if (clientSocket < 0) {
        logMessage("Failed to create socket", "ERROR");
        return false;
    }

    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, serverIp.c_str(), &serverAddr.sin_addr) <= 0) {
        logMessage("Invalid server address", "ERROR");
        closesocket(clientSocket);
        clientSocket = -1;
        return false;
    }

    if (::connect(clientSocket, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        logMessage("Failed to connect to server", "ERROR");
        closesocket(clientSocket);
        clientSocket = -1;
        return false;
    }

    logMessage("Connected to server " + serverIp + ":" + std::to_string(port), "INFO");

    // Perform secure handshake
    if (!performHandshake()) {
        logMessage("Handshake failed", "ERROR");
        closesocket(clientSocket);
        clientSocket = -1;
        return false;
    }

    shouldRun = true;
    messageThread = std::thread(messageLoop);

    return true;
}

void disconnectFromServer()
{
    std::lock_guard<std::mutex> lock(clientMutex);
    
    shouldRun = false;
    
    if (clientSocket >= 0) {
        closesocket(clientSocket);
        clientSocket = -1;
    }
    
    if (messageThread.joinable()) {
        messageThread.join();
    }
}

bool sendMessage(const std::string& message)
{
    std::lock_guard<std::mutex> lock(clientMutex);
    
    if (clientSocket < 0 || !shouldRun) {
        return false;
    }
    
    try {
        std::vector<uint8_t> encrypted_data = cryptoManager->encrypt_message(
            sessionKey, message, currentSession.session_id, messageCounter++);
        
        SecureComm::MessageHeader header;
        header.version = SecureComm::ProtocolVersion::V1_0;
        header.type = SecureComm::MessageType::ENCRYPTED_MESSAGE;
        header.sequence_number = messageCounter - 1;
        header.timestamp = SecureComm::get_current_timestamp_seconds();
        header.payload_size = static_cast<uint32_t>(encrypted_data.size());
        header.flags = 0;
        
        std::vector<uint8_t> packet;
        packet.resize(sizeof(SecureComm::MessageHeader) + encrypted_data.size());
        
        std::memcpy(packet.data(), &header, sizeof(SecureComm::MessageHeader));
        std::memcpy(packet.data() + sizeof(SecureComm::MessageHeader), 
                   encrypted_data.data(), encrypted_data.size());
        
        return sendData(packet);
        
    } catch (const std::exception& e) {
        logMessage("Failed to encrypt/send message: " + std::string(e.what()), "ERROR");
        return false;
    }
}

bool performHandshake()
{
    try {
        // Send handshake init
        SecureComm::HandshakeMessage handshake_init;
        handshake_init.version = SecureComm::ProtocolVersion::V1_0;
        handshake_init.forward_secrecy_type = SecureComm::ForwardSecrecyType::DH_2048;
        handshake_init.client_public_key_size = static_cast<uint32_t>(clientKeypair.public_key.size());
        
        SecureComm::MessageHeader header;
        header.version = SecureComm::ProtocolVersion::V1_0;
        header.type = SecureComm::MessageType::HANDSHAKE_INIT;
        header.sequence_number = messageCounter++;
        header.timestamp = SecureComm::get_current_timestamp_seconds();
        header.payload_size = sizeof(SecureComm::HandshakeMessage) + handshake_init.client_public_key_size;
        header.flags = 0;
        
        std::vector<uint8_t> packet;
        packet.resize(sizeof(SecureComm::MessageHeader) + header.payload_size);
        
        std::memcpy(packet.data(), &header, sizeof(SecureComm::MessageHeader));
        std::memcpy(packet.data() + sizeof(SecureComm::MessageHeader), &handshake_init, sizeof(SecureComm::HandshakeMessage));
        std::memcpy(packet.data() + sizeof(SecureComm::MessageHeader) + sizeof(SecureComm::HandshakeMessage), 
                   clientKeypair.public_key.data(), clientKeypair.public_key.size());
        
        if (!sendData(packet)) {
            return false;
        }
        
        // Receive handshake response
        std::vector<uint8_t> response_data = receiveData();
        if (response_data.empty()) {
            return false;
        }
        
        if (response_data.size() < sizeof(SecureComm::MessageHeader)) {
            return false;
        }
        
        SecureComm::MessageHeader response_header;
        std::memcpy(&response_header, response_data.data(), sizeof(SecureComm::MessageHeader));
        
        if (response_header.type != SecureComm::MessageType::HANDSHAKE_RESPONSE) {
            return false;
        }
        
        // Process handshake response and establish session
        std::vector<uint8_t> payload(response_data.begin() + sizeof(SecureComm::MessageHeader), response_data.end());
        
        if (payload.size() < sizeof(SecureComm::HandshakeMessage)) {
            return false;
        }
        
        SecureComm::HandshakeMessage handshake_response;
        std::memcpy(&handshake_response, payload.data(), sizeof(SecureComm::HandshakeMessage));
        
        // Extract server public key and session info
        size_t offset = sizeof(SecureComm::HandshakeMessage);
        if (payload.size() < offset + handshake_response.server_public_key_size + sizeof(SecureComm::SessionInfo)) {
            return false;
        }
        
        std::vector<uint8_t> server_public_key(payload.begin() + offset, 
                                              payload.begin() + offset + handshake_response.server_public_key_size);
        offset += handshake_response.server_public_key_size;
        
        std::memcpy(&currentSession, payload.data() + offset, sizeof(SecureComm::SessionInfo));
        
        // Generate session key using DH
        sessionKey = cryptoManager->generate_session_key(clientKeypair, server_public_key);
        
        logMessage("Handshake completed successfully", "SUCCESS");
        return true;
        
    } catch (const std::exception& e) {
        logMessage("Handshake failed: " + std::string(e.what()), "ERROR");
        return false;
    }
}

std::string receiveEncryptedMessage()
{
    std::vector<uint8_t> encrypted_data = receiveData();
    if (encrypted_data.empty()) {
        return "";
    }
    
    if (encrypted_data.size() < sizeof(SecureComm::MessageHeader)) {
        return "";
    }
    
    SecureComm::MessageHeader header;
    std::memcpy(&header, encrypted_data.data(), sizeof(SecureComm::MessageHeader));
    
    if (header.type == SecureComm::MessageType::ENCRYPTED_MESSAGE) {
        std::vector<uint8_t> payload(encrypted_data.begin() + sizeof(SecureComm::MessageHeader), encrypted_data.end());
        
        try {
            std::string message = cryptoManager->decrypt_message(sessionKey, payload, currentSession.session_id);
            return message;
        } catch (const std::exception& e) {
            logMessage("Failed to decrypt message: " + std::string(e.what()), "ERROR");
            return "";
        }
    } else if (header.type == SecureComm::MessageType::ERROR_MESSAGE) {
        std::vector<uint8_t> payload(encrypted_data.begin() + sizeof(SecureComm::MessageHeader), encrypted_data.end());
        if (payload.size() >= sizeof(SecureComm::ErrorCode)) {
            SecureComm::ErrorCode error_code = *reinterpret_cast<const SecureComm::ErrorCode*>(payload.data());
            logMessage("Server error: " + SecureComm::error_code_to_string(error_code), "ERROR");
        }
        return "";
    } else {
        logMessage("Unexpected message type: " + SecureComm::message_type_to_string(header.type), "WARNING");
        return "";
    }
}

std::vector<uint8_t> receiveData()
{
    std::vector<uint8_t> data;
    char buffer[4096];
    
    while (shouldRun) {
        int bytes_received = recv(clientSocket, buffer, sizeof(buffer), 0);
        if (bytes_received <= 0) {
            if (bytes_received == 0) {
                logMessage("Server closed connection", "WARNING");
            } else {
                logMessage("Failed to receive data from server", "ERROR");
            }
            shouldRun = false;
            break;
        }
        
        data.insert(data.end(), buffer, buffer + bytes_received);
        
        // Check if we have a complete message
        if (data.size() >= sizeof(SecureComm::MessageHeader)) {
            SecureComm::MessageHeader header;
            std::memcpy(&header, data.data(), sizeof(SecureComm::MessageHeader));
            
            if (data.size() >= sizeof(SecureComm::MessageHeader) + header.payload_size) {
                return data;
            }
        }
    }
    
    return std::vector<uint8_t>();
}

bool sendData(const std::vector<uint8_t>& data)
{
    int total_sent = 0;
    while (total_sent < static_cast<int>(data.size()) && shouldRun) {
        int bytes_sent = send(clientSocket, 
                             reinterpret_cast<const char*>(data.data() + total_sent), 
                             static_cast<int>(data.size() - total_sent), 0);
        if (bytes_sent <= 0) {
            logMessage("Failed to send data to server", "ERROR");
            return false;
        }
        total_sent += bytes_sent;
    }
    return total_sent == static_cast<int>(data.size());
}

void messageLoop()
{
    while (shouldRun) {
        std::string message = receiveEncryptedMessage();
        if (!message.empty()) {
            logMessage("Received: " + message, "RECEIVED");
        }
        
        if (!shouldRun) {
            break;
        }
        
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void logMessage(const std::string& message, const std::string& type)
{
    // Get current time
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto tm = *std::localtime(&time_t);
    
    char timeStr[9];
    std::strftime(timeStr, sizeof(timeStr), "%H:%M:%S", &tm);
    
    std::string formattedMessage = "[" + std::string(timeStr) + "] " + type + ": " + message + "\r\n";
    
    // Append to message display
    int length = GetWindowTextLength(hMessageDisplay);
    SendMessage(hMessageDisplay, EM_SETSEL, length, length);
    SendMessage(hMessageDisplay, EM_REPLACESEL, FALSE, (LPARAM)formattedMessage.c_str());
    
    // Scroll to bottom
    SendMessage(hMessageDisplay, EM_SCROLLCARET, 0, 0);
} 