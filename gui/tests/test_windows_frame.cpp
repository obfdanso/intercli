// Native message handling of the custom title bar (Windows only).

#include "windows_frame.h"

#include <QQuickWindow>
#include <QScreen>
#include <QSettings>
#include <QTemporaryDir>
#include <QtTest>

#ifdef Q_OS_WIN
#include <windows.h>
#endif

using namespace Intercli;

#ifdef Q_OS_WIN
namespace {
int hitTest(QQuickWindow& window, int x, int y) {
    HWND hwnd = reinterpret_cast<HWND>(window.winId());
    POINT pt = {x, y};
    ClientToScreen(hwnd, &pt);
    return static_cast<int>(SendMessageW(hwnd, WM_NCHITTEST, 0, MAKELPARAM(pt.x, pt.y)));
}
} // namespace
#endif

class TestWindowsFrame : public QObject {
    Q_OBJECT
private slots:
#ifdef Q_OS_WIN
    // A real mouse click is queued, and Qt shows it to the filter only from the
    // event loop, with no result slot (nullptr). Clicking maximise used to
    // write through that null pointer and crash the app.
    void messages_without_a_result_never_crash() {
        QQuickWindow window;
        window.resize(800, 600);
        window.create();
        WindowsFrame frame;
        frame.attach(&window);
        frame.setCaptionRects(QRectF(0, 0, 662, 32), QRectF(662, 0, 46, 32), QRectF(708, 0, 46, 32),
                              QRectF(754, 0, 46, 32));

        HWND hwnd = reinterpret_cast<HWND>(window.winId());
        for (UINT message : {UINT(WM_NCLBUTTONDOWN), UINT(WM_NCLBUTTONUP), UINT(WM_NCLBUTTONDBLCLK),
                             UINT(WM_NCMOUSEMOVE), UINT(WM_NCHITTEST), UINT(WM_NCCALCSIZE)}) {
            MSG msg = {};
            msg.hwnd = hwnd;
            msg.message = message;
            msg.wParam = message == WM_NCCALCSIZE ? TRUE : HTMAXBUTTON;
            frame.nativeEventFilter("windows_generic_MSG", &msg, nullptr);
        }
        // Messages that need an answer are left to Windows when there is no slot.
        MSG hit = {};
        hit.hwnd = hwnd;
        hit.message = WM_NCHITTEST;
        QVERIFY(!frame.nativeEventFilter("windows_generic_MSG", &hit, nullptr));
    }

    void the_window_procedure_pass_still_handles_maximise() {
        QQuickWindow window;
        window.resize(800, 600);
        window.create();
        WindowsFrame frame;
        frame.attach(&window);

        MSG msg = {};
        msg.hwnd = reinterpret_cast<HWND>(window.winId());
        msg.message = WM_NCLBUTTONDOWN;
        msg.wParam = HTMAXBUTTON;
        qintptr result = -1;
        QVERIFY(frame.nativeEventFilter("windows_generic_MSG", &msg, &result));
        QCOMPARE(result, qintptr(0));
        QVERIFY(frame.maxPressed());
    }

    void click_on_maximise_maximises_and_restores() {
        QQuickWindow window;
        window.setFlags(Qt::Window | Qt::FramelessWindowHint);
        window.resize(800, 600);
        window.show();
        QVERIFY(QTest::qWaitForWindowExposed(&window));
        WindowsFrame frame;
        frame.attach(&window);

        auto click = [&] {
            for (UINT message : {UINT(WM_NCLBUTTONDOWN), UINT(WM_NCLBUTTONUP)}) {
                MSG msg = {};
                msg.hwnd = reinterpret_cast<HWND>(window.winId());
                msg.message = message;
                msg.wParam = HTMAXBUTTON;
                qintptr result = -1;
                QVERIFY(frame.nativeEventFilter("windows_generic_MSG", &msg, &result));
            }
        };
        click();
        QTRY_VERIFY(window.windowStates() & Qt::WindowMaximized);
        QTRY_VERIFY(frame.maximized());
        click();
        QTRY_VERIFY(!(window.windowStates() & Qt::WindowMaximized));
    }

    // The real path: the click is posted to the queue, as the mouse does.
    void queued_click_on_maximise_maximises() {
        QQuickWindow window;
        window.setFlags(Qt::Window | Qt::FramelessWindowHint);
        window.resize(800, 600);
        window.show();
        QVERIFY(QTest::qWaitForWindowExposed(&window));
        WindowsFrame frame;
        frame.attach(&window);
        frame.setCaptionRects(QRectF(0, 0, 662, 32), QRectF(662, 0, 46, 32), QRectF(708, 0, 46, 32),
                              QRectF(754, 0, 46, 32));
        HWND hwnd = reinterpret_cast<HWND>(window.winId());
        PostMessageW(hwnd, WM_NCLBUTTONDOWN, HTMAXBUTTON, 0);
        PostMessageW(hwnd, WM_NCLBUTTONUP, HTMAXBUTTON, 0);
        QTRY_VERIFY(IsZoomed(hwnd));
    }

    // --- compact sign-in window --------------------------------------------

    void initTestCase() {
        // Keep test settings out of the user's real settings.
        QSettings::setDefaultFormat(QSettings::IniFormat);
        QSettings::setPath(QSettings::IniFormat, QSettings::UserScope, settingsDir.path());
    }

    void compact_window_is_small_fixed_and_not_maximisable() {
        QQuickWindow window;
        window.setFlags(Qt::Window | Qt::FramelessWindowHint);
        window.resize(1100, 700);
        window.show();
        QVERIFY(QTest::qWaitForWindowExposed(&window));
        WindowsFrame frame;
        frame.attach(&window);

        frame.enterCompact();
        QTRY_COMPARE(window.size(), WindowsFrame::compactSize());
        QVERIFY(!frame.resizable());
        const qreal dpr = window.devicePixelRatio();
        // No resize edges, and double-click or Win+Up can't maximise it.
        QCOMPARE(hitTest(window, 1, int(200 * dpr)), int(HTCLIENT));
        HWND hwnd = reinterpret_cast<HWND>(window.winId());
        QVERIFY(!(GetWindowLongPtrW(hwnd, GWL_STYLE) & WS_MAXIMIZEBOX));
        frame.toggleMaximize();
        QTest::qWait(200);
        QVERIFY(!(window.windowStates() & Qt::WindowMaximized));

        // Centred on its screen.
        const QRect avail = window.screen()->availableGeometry();
        QVERIFY(qAbs(window.geometry().center().x() - avail.center().x()) <= 2);
    }

    void full_window_comes_back_where_it_was() {
        QQuickWindow window;
        window.setFlags(Qt::Window | Qt::FramelessWindowHint);
        window.resize(500, 500);
        window.show();
        QVERIFY(QTest::qWaitForWindowExposed(&window));
        WindowsFrame frame;
        frame.attach(&window);

        frame.enterFull();
        QVERIFY(frame.resizable());
        window.setGeometry(150, 120, 1000, 650);
        QTest::qWait(200);
        const QRect full = window.geometry();

        frame.enterCompact();
        QTRY_COMPARE(window.size(), WindowsFrame::compactSize());
        frame.enterFull();
        QTRY_COMPARE(window.geometry(), full);
        HWND hwnd = reinterpret_cast<HWND>(window.winId());
        QVERIFY(GetWindowLongPtrW(hwnd, GWL_STYLE) & WS_MAXIMIZEBOX);
        const qreal dpr = window.devicePixelRatio();
        QCOMPARE(hitTest(window, 1, int(300 * dpr)), int(HTLEFT));
    }

    void signing_out_while_maximised_goes_back_to_compact() {
        QQuickWindow window;
        window.setFlags(Qt::Window | Qt::FramelessWindowHint);
        window.show();
        QVERIFY(QTest::qWaitForWindowExposed(&window));
        WindowsFrame frame;
        frame.attach(&window);
        frame.enterFull();
        frame.toggleMaximize();
        HWND hwnd = reinterpret_cast<HWND>(window.winId());
        QTRY_VERIFY(IsZoomed(hwnd));
        frame.enterCompact();
        QTRY_VERIFY(!IsZoomed(hwnd));
        QTRY_COMPARE(window.size(), WindowsFrame::compactSize());
    }

    void full_window_remembers_being_maximised_across_runs() {
        QSettings().clear();  // start from a first run, whatever earlier tests saved
        {
            QQuickWindow window;
            window.setFlags(Qt::Window | Qt::FramelessWindowHint);
            window.show();
            QVERIFY(QTest::qWaitForWindowExposed(&window));
            WindowsFrame frame;
            frame.attach(&window);
            frame.enterFull();
            frame.toggleMaximize();
            QTRY_VERIFY(window.windowStates() & Qt::WindowMaximized);
            frame.saveFullPlacement();
        }
        QQuickWindow window;
        window.setFlags(Qt::Window | Qt::FramelessWindowHint);
        window.show();
        QVERIFY(QTest::qWaitForWindowExposed(&window));
        WindowsFrame frame;
        frame.attach(&window);
        frame.enterCompact();
        QTRY_VERIFY(!(window.windowStates() & Qt::WindowMaximized));
        frame.enterFull();
        QTRY_VERIFY(window.windowStates() & Qt::WindowMaximized);
    }
#endif

private:
    QTemporaryDir settingsDir;
};

QTEST_MAIN(TestWindowsFrame)
#include "test_windows_frame.moc"
