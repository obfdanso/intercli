#include "gui_client.h"
#include <QApplication>
#include <QDateTime>
#include <QScrollBar>
#include <QMessageBox>
#include <QTimer>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
#endif

#include <cstring>

// GuiClient Implementation
GuiClient::GuiClient(QWidget *parent)
    : QMainWindow(parent)
    , isConnected_(false)
    , clientThread_(nullptr)
    , workerThread_(nullptr)
{
    setWindowTitle("Secure Communication Client");
    setMinimumSize(800, 600);
    
    setupUI();
    setupConnections();
    
    // Set default values
    serverIpEdit_->setText("127.0.0.1");
    serverPortSpinBox_->setValue(SecureComm::DEFAULT_PORT);
    
    logMessage("GUI Client initialized. Ready to connect to server.", "INFO");
}

GuiClient::~GuiClient()
{
    if (isConnected_) {
        disconnectFromServer();
    }
}

void GuiClient::setupUI()
{
    centralWidget_ = new QWidget(this);
    setCentralWidget(centralWidget_);
    
    mainLayout_ = new QVBoxLayout(centralWidget_);
    
    // Connection Group
    connectionGroup_ = new QGroupBox("Server Connection", this);
    connectionLayout_ = new QGridLayout(connectionGroup_);
    
    connectionLayout_->addWidget(new QLabel("Server IP:"), 0, 0);
    serverIpEdit_ = new QLineEdit(this);
    connectionLayout_->addWidget(serverIpEdit_, 0, 1);
    
    connectionLayout_->addWidget(new QLabel("Port:"), 0, 2);
    serverPortSpinBox_ = new QSpinBox(this);
    serverPortSpinBox_->setRange(1, 65535);
    connectionLayout_->addWidget(serverPortSpinBox_, 0, 3);
    
    connectButton_ = new QPushButton("Connect", this);
    connectionLayout_->addWidget(connectButton_, 0, 4);
    
    disconnectButton_ = new QPushButton("Disconnect", this);
    disconnectButton_->setEnabled(false);
    connectionLayout_->addWidget(disconnectButton_, 0, 5);
    
    connectionStatusLabel_ = new QLabel("Disconnected", this);
    connectionLayout_->addWidget(connectionStatusLabel_, 1, 0, 1, 6);
    
    mainLayout_->addWidget(connectionGroup_);
    
    // Message Group
    messageGroup_ = new QGroupBox("Secure Messages", this);
    messageLayout_ = new QVBoxLayout(messageGroup_);
    
    messageDisplay_ = new QTextEdit(this);
    messageDisplay_->setReadOnly(true);
    messageLayout_->addWidget(messageDisplay_);
    
    inputLayout_ = new QHBoxLayout();
    messageInput_ = new QLineEdit(this);
    messageInput_->setPlaceholderText("Type your secure message here...");
    messageInput_->setEnabled(false);
    inputLayout_->addWidget(messageInput_);
    
    sendButton_ = new QPushButton("Send", this);
    sendButton_->setEnabled(false);
    inputLayout_->addWidget(sendButton_);
    
    keyRotationButton_ = new QPushButton("Rotate Keys", this);
    keyRotationButton_->setEnabled(false);
    inputLayout_->addWidget(keyRotationButton_);
    
    messageLayout_->addLayout(inputLayout_);
    mainLayout_->addWidget(messageGroup_);
    
    // Status Bar
    statusBar_ = statusBar();
    statusBar_->showMessage("Ready");
}

void GuiClient::setupConnections()
{
    connect(connectButton_, &QPushButton::clicked, this, &GuiClient::connectToServer);
    connect(disconnectButton_, &QPushButton::clicked, this, &GuiClient::disconnectFromServer);
    connect(sendButton_, &QPushButton::clicked, this, &GuiClient::sendMessage);
    connect(keyRotationButton_, &QPushButton::clicked, this, &GuiClient::onKeyRotationRequested);
    connect(messageInput_, &QLineEdit::returnPressed, this, &GuiClient::sendMessage);
}

void GuiClient::connectToServer()
{
    QString serverIp = serverIpEdit_->text().trimmed();
    uint16_t port = static_cast<uint16_t>(serverPortSpinBox_->value());
    
    if (serverIp.isEmpty()) {
        QMessageBox::warning(this, "Invalid Input", "Please enter a valid server IP address.");
        return;
    }
    
    logMessage("Attempting to connect to " + serverIp + ":" + QString::number(port), "INFO");
    
    // For now, just simulate connection
    isConnected_ = true;
    updateConnectionUI(true);
    logMessage("Connected to server (simulated)", "SUCCESS");
}

void GuiClient::disconnectFromServer()
{
    isConnected_ = false;
    updateConnectionUI(false);
    logMessage("Disconnected from server", "WARNING");
}

void GuiClient::sendMessage()
{
    QString message = messageInput_->text().trimmed();
    if (message.isEmpty()) {
        return;
    }
    
    if (isConnected_) {
        logMessage("Sent: " + message, "SENT");
        messageInput_->clear();
        
        // Simulate receiving a response
        QTimer::singleShot(1000, [this, message]() {
            logMessage("Received: " + message + " (encrypted response)", "RECEIVED");
        });
    }
}

void GuiClient::onConnectionStatusChanged(bool connected)
{
    isConnected_ = connected;
    updateConnectionUI(connected);
}

void GuiClient::onMessageReceived(const QString& message)
{
    logMessage("Received: " + message, "RECEIVED");
}

void GuiClient::onErrorOccurred(const QString& error)
{
    logMessage("Error: " + error, "ERROR");
    QMessageBox::critical(this, "Connection Error", error);
}

void GuiClient::onKeyRotationRequested()
{
    if (isConnected_) {
        logMessage("Key rotation requested", "INFO");
    }
}

void GuiClient::updateConnectionUI(bool connected)
{
    connectButton_->setEnabled(!connected);
    disconnectButton_->setEnabled(connected);
    sendButton_->setEnabled(connected);
    keyRotationButton_->setEnabled(connected);
    messageInput_->setEnabled(connected);
    serverIpEdit_->setEnabled(!connected);
    serverPortSpinBox_->setEnabled(!connected);
    
    if (connected) {
        connectionStatusLabel_->setText("Connected");
    } else {
        connectionStatusLabel_->setText("Disconnected");
    }
}

void GuiClient::logMessage(const QString& message, const QString& type)
{
    QString timestamp = QDateTime::currentDateTime().toString("hh:mm:ss");
    QString formattedMessage = QString("[%1] %2: %3").arg(timestamp, type, message);
    
    messageDisplay_->append(formattedMessage);
    
    // Auto-scroll to bottom
    QScrollBar* scrollbar = messageDisplay_->verticalScrollBar();
    scrollbar->setValue(scrollbar->maximum());
}

void GuiClient::updateStatusBar()
{
    if (isConnected_) {
        statusBar_->showMessage("Connected - Ready to send secure messages");
    } else {
        statusBar_->showMessage("Disconnected");
    }
}

// Main function
int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    
    GuiClient window;
    window.show();
    
    return app.exec();
} 