// intercli desktop app entry point.

#include <QFont>
#include <QFontDatabase>
#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QQuickStyle>
#include <QQuickWindow>

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

    QQmlApplicationEngine engine;
    QObject::connect(&engine, &QQmlApplicationEngine::objectCreationFailed, &app,
                     [] { QCoreApplication::exit(1); }, Qt::QueuedConnection);
    engine.loadFromModule("Intercli", "Main");

    return app.exec();
}
