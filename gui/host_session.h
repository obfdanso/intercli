#pragma once

#include "discovery.h"

#include <QByteArray>
#include <QObject>
#include <QString>
#include <QTimer>

#include <memory>
#include <thread>

namespace SecureComm {
class SecureServer;
}

namespace Intercli {

// Hosting a chat from the app: runs the chat server on this PC (on 8080, or
// the next free port from 8082 to 8089), answers "who is hosting?" on the
// local network, and keeps the chat's id, room code and identity key so the
// chat is the same one every time it is hosted.
class HostSession : public QObject {
    Q_OBJECT
public:
    // dataDir holds host.key, the DPAPI-protected identity key.
    explicit HostSession(const QString& dataDir, QObject* parent = nullptr);
    ~HostSession() override;

    // Emits started(port) or failed(reason).
    void start(const QString& hostName, quint16 discoveryPort = kDiscoveryPort);
    void stop();  // safe if not started; the server and beacon are gone when it returns
    bool running() const;

    QString chatId() const { return chat_id_; }
    QString roomCode() const { return room_code_; }  // normalised, 6 characters
    QString chatName() const { return chat_name_; }
    quint16 port() const { return port_; }
    int people() const { return people_; }
    // Asks the server right now (people() is refreshed every couple of seconds).
    int peopleNow() const;
    QByteArray identityPublic() const { return identity_public_; }
    QString safetyCode() const;

    void setPeoplePollForTests(int ms);

signals:
    void started(quint16 port);
    void failed(const QString& reason);
    void peopleChanged();

private:
    void pollPeople();
    void announce();

    QString chat_id_;
    QString room_code_;
    QString chat_name_;
    QString host_name_;
    QByteArray identity_private_;
    QByteArray identity_public_;
    quint16 port_ = 0;
    int people_ = 0;

    std::unique_ptr<SecureComm::SecureServer> server_;
    std::thread runner_;
    ChatBeacon beacon_;
    QTimer people_timer_;
};

} // namespace Intercli
