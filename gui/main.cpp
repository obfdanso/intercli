// intercli desktop app entry point.

#include "chat_controller.h"
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

#ifdef Q_OS_WIN
#include <windows.h>
#endif

namespace {

// Windows remembers the normal (restored) rectangle even while a window is
// maximised, so the placement API saves both the size and the maximised state.
void restoreGeometry(QQuickWindow* window) {
    QSettings settings;
    const QRect rect = settings.value("windowGeometry").toRect();
    const bool maximized = settings.value("windowMaximized", false).toBool();
#ifdef Q_OS_WIN
    if (rect.isValid()) {
        const RECT r = {rect.left(), rect.top(), rect.right() + 1, rect.bottom() + 1};
        // Ignore a saved rectangle that is no longer on any monitor.
        if (MonitorFromRect(&r, MONITOR_DEFAULTTONULL)) {
            WINDOWPLACEMENT wp = {};
            wp.length = sizeof(wp);
            HWND hwnd = reinterpret_cast<HWND>(window->winId());
            GetWindowPlacement(hwnd, &wp);
            wp.rcNormalPosition = r;
            wp.showCmd = maximized ? SW_SHOWMAXIMIZED : SW_SHOWNORMAL;
            SetWindowPlacement(hwnd, &wp);
        }
    }
#else
    if (rect.isValid() && QGuiApplication::screenAt(rect.center())) {
        window->setGeometry(rect);
    }
    if (maximized) {
        window->showMaximized();
    }
#endif
}

void saveGeometry(QQuickWindow* window) {
    QSettings settings;
#ifdef Q_OS_WIN
    WINDOWPLACEMENT wp = {};
    wp.length = sizeof(wp);
    if (!GetWindowPlacement(reinterpret_cast<HWND>(window->winId()), &wp)) {
        return;
    }
    const RECT& r = wp.rcNormalPosition;
    settings.setValue("windowGeometry", QRect(QPoint(r.left, r.top), QPoint(r.right - 1, r.bottom - 1)));
    settings.setValue("windowMaximized", wp.showCmd == SW_SHOWMAXIMIZED);
#else
    settings.setValue("windowGeometry", window->geometry());
    settings.setValue("windowMaximized", bool(window->windowStates() & Qt::WindowMaximized));
#endif
}

} // namespace

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

    Intercli::ChatController chat;
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
    restoreGeometry(window);
    // Saved while the native window still exists.
    QObject::connect(window, &QQuickWindow::closing, window, [window] { saveGeometry(window); });

    return app.exec();
}
