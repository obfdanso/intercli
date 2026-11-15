// intercli desktop app entry point.

#include "chat_controller.h"
#include "history_store.h"
#include "host_session.h"
#include "key_vault.h"
#include "windows_frame.h"

#include <QFont>
#include <QFontDatabase>
#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QtQml>
#include <QQuickStyle>
#include <QQuickWindow>
#include <QScreen>
#include <QSettings>
#include <QStandardPaths>

#ifdef Q_OS_WIN
#include <windows.h>
#endif

int main(int argc, char* argv[]) {
    QGuiApplication app(argc, argv);
    QGuiApplication::setApplicationName("intercli");
    QGuiApplication::setOrganizationName("intercli");

    // Native text rendering keeps small UI text crisp on Windows.
    QQuickWindow::setTextRenderType(QQuickWindow::NativeTextRendering);
    // Basic is the plain, fully restylable Controls style; nothing native or
    // Material leaks into the custom look.
    QQuickStyle::setStyle("Basic");

    const int font_id = QFontDatabase::addApplicationFont(":/qt/qml/Intercli/fonts/InterVariable.ttf");
    QFont font(font_id >= 0 ? QFontDatabase::applicationFontFamilies(font_id).value(0)
                            : QStringLiteral("Segoe UI Variable Text"));
    font.setPixelSize(13);
    font.setHintingPreference(QFont::PreferNoHinting);
    QGuiApplication::setFont(font);

    // Saved messages live in the user's app data folder. If the store can't be
    // opened the app still runs, without the option to save.
    const QString data_dir = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    Intercli::HistoryStore history(data_dir + "/history.db",
                                   Intercli::loadOrCreateHistoryKey(data_dir + "/history.key"));
    QString history_error;
    const bool history_ok = history.open(&history_error);
    if (!history_ok) {
        qWarning("Saved messages unavailable: %s", qPrintable(history_error));
    }

    // Hosting a chat from this PC (the chat id, room code and identity key live here too).
    Intercli::HostSession host(data_dir);
    Intercli::ChatController chat(history_ok ? &history : nullptr, &host);
    qmlRegisterSingletonInstance("Intercli.Backend", 1, 0, "Chat", &chat);
    Intercli::WindowsFrame frame;
    qmlRegisterSingletonInstance("Intercli.Backend", 1, 0, "Frame", &frame);

    QQmlApplicationEngine engine;
    QObject::connect(&engine, &QQmlApplicationEngine::objectCreationFailed, &app,
                     [] { QCoreApplication::exit(1); }, Qt::QueuedConnection);
    engine.loadFromModule("Intercli", "Main");
    if (engine.rootObjects().isEmpty()) {
        return 1;
    }
    auto* window = qobject_cast<QQuickWindow*>(engine.rootObjects().constFirst());
    frame.attach(window);
    // Start as the small sign-in window; it opens up once signed in.
    frame.enterCompact();
    // Flash the taskbar button when a message arrives while the app is in the background.
    QObject::connect(&chat, &Intercli::ChatController::messageArrived, window, [window] {
        if (!window->isActive()) {
            window->alert(0);
        }
    });
    // Saved while the native window still exists.
    QObject::connect(window, &QQuickWindow::closing, &frame, [&frame] { frame.saveFullPlacement(); });

    return app.exec();
}
