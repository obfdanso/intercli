// Native message handling of the custom title bar (Windows only).

#include "windows_frame.h"

#include <QQuickWindow>
#include <QtTest>

#ifdef Q_OS_WIN
#include <windows.h>
#endif

using namespace Intercli;

class TestWindowsFrame : public QObject {
    Q_OBJECT
private slots:
#ifdef Q_OS_WIN
    // A real mouse click is queued, and Qt first shows queued messages to the
    // filter without a result slot (nullptr). Clicking maximise used to write
    // through that null pointer and crash the app.
    void queued_messages_without_a_result_are_left_alone() {
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
            msg.wParam = HTMAXBUTTON;
            QVERIFY(!frame.nativeEventFilter("windows_generic_MSG", &msg, nullptr));
        }
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
#endif
};

QTEST_MAIN(TestWindowsFrame)
#include "test_windows_frame.moc"
