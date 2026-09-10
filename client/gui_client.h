#pragma once

#include <QMainWindow>
#include <QTextEdit>
#include <QLineEdit>
#include <QPushButton>
#include <QLabel>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QStatusBar>
#include <QTimer>
#include <QSpinBox>

#include "common.h"

class GuiClient : public QMainWindow
{
    Q_OBJECT

public:
    GuiClient(QWidget *parent = nullptr);
    ~GuiClient();

private slots:
    void connectToServer();
    void disconnectFromServer();
    void sendMessage();
    void onKeyRotationRequested();

private:
    void setupUI();
    void setupConnections();
    void updateConnectionUI(bool connected);
    void logMessage(const QString& message, const QString& type = "INFO");

    // UI Components
    QWidget* centralWidget_;
    QVBoxLayout* mainLayout_;
    
    // Connection Group
    QGroupBox* connectionGroup_;
    QGridLayout* connectionLayout_;
    QLineEdit* serverIpEdit_;
    QSpinBox* serverPortSpinBox_;
    QPushButton* connectButton_;
    QPushButton* disconnectButton_;
    QLabel* connectionStatusLabel_;
    
    // Message Group
    QGroupBox* messageGroup_;
    QVBoxLayout* messageLayout_;
    QTextEdit* messageDisplay_;
    QHBoxLayout* inputLayout_;
    QLineEdit* messageInput_;
    QPushButton* sendButton_;
    QPushButton* keyRotationButton_;
    
    // Status
    QStatusBar* statusBar_;
    
    // State
    bool isConnected_;
}; 