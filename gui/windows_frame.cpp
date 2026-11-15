#include "windows_frame.h"

#include <QGuiApplication>
#include <QQuickWindow>
#include <QScreen>
#include <QSettings>
#include <QTimer>

#ifdef Q_OS_WIN
#include <windows.h>
#include <windowsx.h>
#include <dwmapi.h>

#ifndef DWMWA_USE_IMMERSIVE_DARK_MODE
#define DWMWA_USE_IMMERSIVE_DARK_MODE 20
#endif
#ifndef DWMWA_WINDOW_CORNER_PREFERENCE
#define DWMWA_WINDOW_CORNER_PREFERENCE 33
#endif
#ifndef DWMWA_SYSTEMBACKDROP_TYPE
#define DWMWA_SYSTEMBACKDROP_TYPE 38
#endif
#endif

namespace Intercli {

WindowsFrame::WindowsFrame(QObject* parent) : QObject(parent) {}

WindowsFrame::~WindowsFrame() {
    if (window_) {
        qApp->removeNativeEventFilter(this);
    }
}

bool WindowsFrame::customFrame() const {
#ifdef Q_OS_WIN
    return true;
#else
    return false;
#endif
}

void WindowsFrame::attach(QQuickWindow* window) {
    window_ = window;
    if (!window_) {
        return;
    }
    connect(window_, &QWindow::windowStateChanged, this, &WindowsFrame::updateMaximized);
    updateMaximized();

#ifdef Q_OS_WIN
    HWND hwnd = reinterpret_cast<HWND>(window_->winId());
    // Cached: calling winId() from the filter after Qt has destroyed the native
    // window would quietly create a new one and keep the app from quitting.
    hwnd_ = reinterpret_cast<quintptr>(hwnd);

    // Qt's frameless flag strips the caption and sizing styles; put them back so
    // Windows still snaps, animates and resizes the window. WM_NCCALCSIZE below
    // then hands the whole window to the client area.
    LONG_PTR style = GetWindowLongPtrW(hwnd, GWL_STYLE);
    style |= WS_CAPTION | WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX | WS_SYSMENU;
    SetWindowLongPtrW(hwnd, GWL_STYLE, style);

    BOOL dark = TRUE;
    DwmSetWindowAttribute(hwnd, DWMWA_USE_IMMERSIVE_DARK_MODE, &dark, sizeof(dark));
    const int round = 2;  // DWMWCP_ROUND
    DwmSetWindowAttribute(hwnd, DWMWA_WINDOW_CORNER_PREFERENCE, &round, sizeof(round));
    // A one-pixel strip of DWM frame keeps the native shadow.
    const MARGINS shadow = {0, 0, 1, 0};
    DwmExtendFrameIntoClientArea(hwnd, &shadow);

    qApp->installNativeEventFilter(this);
    SetWindowPos(hwnd, nullptr, 0, 0, 0, 0,
                 SWP_FRAMECHANGED | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
#endif
}

void WindowsFrame::updateMaximized() {
    const bool m = window_ && (window_->windowStates() & Qt::WindowMaximized);
    if (m != maximized_) {
        maximized_ = m;
        emit maximizedChanged();
    }
}

void WindowsFrame::setCaptionRects(const QRectF& dragArea, const QRectF& minButton, const QRectF& maxButton,
                                   const QRectF& closeButton) {
    drag_ = dragArea;
    min_ = minButton;
    max_ = maxButton;
    close_ = closeButton;
}

void WindowsFrame::minimize() {
    if (window_) {
        window_->showMinimized();
    }
}

void WindowsFrame::toggleMaximize() {
    if (!window_ || !resizable_) {
        return;
    }
#ifdef Q_OS_WIN
    // A real Windows maximise, the same as double-clicking the title or Win+Up.
    // Qt's own maximise of a frameless window only resizes it to the work area,
    // which Windows doesn't treat as maximised (no restore size, no snap).
    if (HWND hwnd = reinterpret_cast<HWND>(hwnd_)) {
        ShowWindow(hwnd, IsZoomed(hwnd) ? SW_RESTORE : SW_MAXIMIZE);
        return;
    }
#endif
    if (maximized_) {
        window_->showNormal();
    } else {
        window_->showMaximized();
    }
}

void WindowsFrame::close() {
    if (window_) {
        window_->close();
    }
}

void WindowsFrame::fixRestoreRect() {
#ifdef Q_OS_WIN
    HWND hwnd = reinterpret_cast<HWND>(hwnd_);
    if (!hwnd || !has_normal_ || !IsZoomed(hwnd)) {
        return;
    }
    WINDOWPLACEMENT wp = {};
    wp.length = sizeof(wp);
    if (!GetWindowPlacement(hwnd, &wp)) {
        return;
    }
    const RECT want = {normal_left_, normal_top_, normal_right_, normal_bottom_};
    if (EqualRect(&wp.rcNormalPosition, &want)) {
        return;
    }
    wp.rcNormalPosition = want;
    wp.showCmd = SW_SHOWMAXIMIZED;
    wp.flags = 0;
    SetWindowPlacement(hwnd, &wp);
#endif
}

void WindowsFrame::setMaximizeAllowed(bool allowed) {
#ifdef Q_OS_WIN
    HWND hwnd = reinterpret_cast<HWND>(hwnd_);
    if (!hwnd) {
        return;
    }
    // Without the maximise style, double-clicking the title and Win+Up cannot
    // maximise the window either.
    LONG_PTR style = GetWindowLongPtrW(hwnd, GWL_STYLE);
    style = allowed ? (style | WS_MAXIMIZEBOX) : (style & ~WS_MAXIMIZEBOX);
    SetWindowLongPtrW(hwnd, GWL_STYLE, style);
    SetWindowPos(hwnd, nullptr, 0, 0, 0, 0,
                 SWP_FRAMECHANGED | SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
#else
    Q_UNUSED(allowed);
#endif
}

void WindowsFrame::enterCompact() {
    if (!window_) {
        return;
    }
    saveFullPlacement();
    full_mode_ = false;
#ifdef Q_OS_WIN
    // Undo a real Windows maximise the same way it was made.
    if (HWND hwnd = reinterpret_cast<HWND>(hwnd_); hwnd && IsZoomed(hwnd)) {
        ShowWindow(hwnd, SW_RESTORE);
    }
#endif
    if (window_->windowStates() & Qt::WindowMaximized) {
        window_->showNormal();
    }
    resizable_ = false;
    emit resizableChanged();
    setMaximizeAllowed(false);

    const QSize size = compactSize();
    window_->setMinimumSize(size);
    window_->setMaximumSize(size);
    window_->resize(size);
    if (QScreen* screen = window_->screen()) {
        const QRect avail = screen->availableGeometry();
        window_->setPosition(avail.center() - QPoint(size.width() / 2, size.height() / 2));
    }
}

void WindowsFrame::enterFull() {
    if (!window_) {
        return;
    }
    full_mode_ = true;
    resizable_ = true;
    emit resizableChanged();
    window_->setMinimumSize(QSize(820, 520));
    window_->setMaximumSize(QSize((1 << 24) - 1, (1 << 24) - 1));  // no limit (QWINDOWSIZE_MAX)
    setMaximizeAllowed(true);
    restoreFullPlacement();
}

// Windows remembers the normal (restored) rectangle even while a window is
// maximised, so the placement API saves both the size and the maximised state.
void WindowsFrame::saveFullPlacement() {
    if (!window_ || !full_mode_) {
        return;
    }
    QSettings settings;
#ifdef Q_OS_WIN
    WINDOWPLACEMENT wp = {};
    wp.length = sizeof(wp);
    if (!hwnd_ || !GetWindowPlacement(reinterpret_cast<HWND>(hwnd_), &wp)) {
        return;
    }
    const RECT& r = wp.rcNormalPosition;
    settings.setValue("windowGeometry", QRect(QPoint(r.left, r.top), QPoint(r.right - 1, r.bottom - 1)));
    settings.setValue("windowMaximized", wp.showCmd == SW_SHOWMAXIMIZED);
#else
    settings.setValue("windowGeometry", window_->geometry());
    settings.setValue("windowMaximized", bool(window_->windowStates() & Qt::WindowMaximized));
#endif
}

void WindowsFrame::restoreFullPlacement() {
    QSettings settings;
    const QRect rect = settings.value("windowGeometry").toRect();
    const bool maximized = settings.value("windowMaximized", false).toBool();
#ifdef Q_OS_WIN
    const RECT r = {rect.left(), rect.top(), rect.right() + 1, rect.bottom() + 1};
    // Ignore a saved rectangle that is no longer on any monitor.
    if (rect.isValid() && hwnd_ && MonitorFromRect(&r, MONITOR_DEFAULTTONULL)) {
        HWND hwnd = reinterpret_cast<HWND>(hwnd_);
        WINDOWPLACEMENT wp = {};
        wp.length = sizeof(wp);
        GetWindowPlacement(hwnd, &wp);
        wp.rcNormalPosition = r;
        wp.showCmd = maximized ? SW_SHOWMAXIMIZED : SW_SHOWNORMAL;
        wp.flags = 0;
        SetWindowPlacement(hwnd, &wp);
        return;
    }
#else
    if (rect.isValid() && QGuiApplication::screenAt(rect.center())) {
        window_->setGeometry(rect);
        if (maximized) {
            window_->showMaximized();
        }
        return;
    }
#endif
    // First run: a comfortable size in the middle of the screen.
    const QSize size(1100, 700);
    window_->resize(size);
    if (QScreen* screen = window_->screen()) {
        const QRect avail = screen->availableGeometry();
        window_->setPosition(avail.center() - QPoint(size.width() / 2, size.height() / 2));
    }
}

void WindowsFrame::setMaxState(bool hovered, bool pressed) {
    if (hovered != max_hovered_ || pressed != max_pressed_) {
        max_hovered_ = hovered;
        max_pressed_ = pressed;
        emit maxButtonChanged();
    }
}

bool WindowsFrame::nativeEventFilter(const QByteArray& eventType, void* message, qintptr* result) {
#ifdef Q_OS_WIN
    // Qt shows mouse input (every real click) to native filters only from the
    // event loop, where there is no result slot: result is null and returning
    // true just stops the message. Other messages come from the window
    // procedure with a result slot. So: never write through a null result,
    // and answer messages that need a result only when there is one.
    if (!window_ || eventType != "windows_generic_MSG") {
        return false;
    }
    MSG* msg = static_cast<MSG*>(message);
    HWND hwnd = reinterpret_cast<HWND>(hwnd_);
    if (!hwnd || msg->hwnd != hwnd) {
        return false;
    }

    const UINT dpi = GetDpiForWindow(hwnd);
    const int frame_x = GetSystemMetricsForDpi(SM_CXSIZEFRAME, dpi) + GetSystemMetricsForDpi(SM_CXPADDEDBORDER, dpi);
    const int frame_y = GetSystemMetricsForDpi(SM_CYSIZEFRAME, dpi) + GetSystemMetricsForDpi(SM_CXPADDEDBORDER, dpi);

    switch (msg->message) {
        case WM_NCDESTROY:
            hwnd_ = 0;
            return false;

        // Qt rewrites the restore rectangle of a frameless window when it is
        // maximised and gets it wrong when the taskbar is at the top or left, so
        // the window comes back shifted. Remember the real one and put it back.
        case WM_WINDOWPOSCHANGED:
            if (!IsZoomed(hwnd) && !IsIconic(hwnd)) {
                WINDOWPLACEMENT wp = {};
                wp.length = sizeof(wp);
                if (GetWindowPlacement(hwnd, &wp)) {
                    normal_left_ = wp.rcNormalPosition.left;
                    normal_top_ = wp.rcNormalPosition.top;
                    normal_right_ = wp.rcNormalPosition.right;
                    normal_bottom_ = wp.rcNormalPosition.bottom;
                    has_normal_ = true;
                }
            }
            return false;
        case WM_SIZE:
            if (msg->wParam == SIZE_MAXIMIZED && has_normal_) {
                QTimer::singleShot(0, this, [this] { fixRestoreRect(); });
            }
            return false;

        case WM_NCCALCSIZE: {
            if (msg->wParam == FALSE || !result) {
                return false;
            }
            auto* params = reinterpret_cast<NCCALCSIZE_PARAMS*>(msg->lParam);
            if (IsZoomed(hwnd)) {
                // A maximised window hangs over the monitor edge by the frame
                // thickness; pull the client area back inside the work area.
                params->rgrc[0].left += frame_x;
                params->rgrc[0].right -= frame_x;
                params->rgrc[0].top += frame_y;
                params->rgrc[0].bottom -= frame_y;
            }
            *result = 0;
            return true;
        }

        case WM_NCHITTEST: {
            if (!result) {
                return false;
            }
            POINT pt = {GET_X_LPARAM(msg->lParam), GET_Y_LPARAM(msg->lParam)};
            RECT wr;
            GetWindowRect(hwnd, &wr);
            ScreenToClient(hwnd, &pt);
            const qreal ratio = window_->devicePixelRatio();
            const QPointF p(pt.x / ratio, pt.y / ratio);

            if (resizable_ && !IsZoomed(hwnd)) {
                const int w = wr.right - wr.left;
                const int h = wr.bottom - wr.top;
                const bool left = pt.x < frame_x;
                const bool right = pt.x >= w - frame_x;
                const bool top = pt.y < frame_y / 2 + 1;
                const bool bottom = pt.y >= h - frame_y;
                if (top && left) { *result = HTTOPLEFT; return true; }
                if (top && right) { *result = HTTOPRIGHT; return true; }
                if (bottom && left) { *result = HTBOTTOMLEFT; return true; }
                if (bottom && right) { *result = HTBOTTOMRIGHT; return true; }
                if (left) { *result = HTLEFT; return true; }
                if (right) { *result = HTRIGHT; return true; }
                if (top) { *result = HTTOP; return true; }
                if (bottom) { *result = HTBOTTOM; return true; }
            }
            if (resizable_ && max_.contains(p)) {
                // Windows 11 shows its snap-layout flyout only for HTMAXBUTTON.
                *result = HTMAXBUTTON;
                return true;
            }
            if (min_.contains(p) || close_.contains(p)) {
                *result = HTCLIENT;
                return true;
            }
            if (drag_.contains(p)) {
                *result = HTCAPTION;
                return true;
            }
            *result = HTCLIENT;
            return true;
        }

        // Windows owns the mouse while it is over HTMAXBUTTON, so the QML button
        // gets its hover and pressed look from here instead.
        case WM_NCMOUSEMOVE:
            if (msg->wParam == HTMAXBUTTON) {
                if (!tracking_nc_leave_) {
                    TRACKMOUSEEVENT tme = {sizeof(tme), TME_LEAVE | TME_NONCLIENT, hwnd, 0};
                    TrackMouseEvent(&tme);
                    tracking_nc_leave_ = true;
                }
                setMaxState(true, max_pressed_);
            } else {
                setMaxState(false, false);
            }
            return false;
        case WM_NCMOUSELEAVE:
            tracking_nc_leave_ = false;
            setMaxState(false, false);
            return false;
        case WM_MOUSEMOVE:
            if (max_hovered_) {
                setMaxState(false, false);
            }
            return false;
        case WM_NCLBUTTONDOWN:
        case WM_NCLBUTTONDBLCLK:
            if (msg->wParam == HTMAXBUTTON) {
                setMaxState(true, true);
                if (result) {
                    *result = 0;
                }
                // Swallowed: otherwise Windows starts its own old-style caption
                // button handling and waits for the mouse in a modal loop.
                return true;
            }
            return false;
        case WM_NCLBUTTONUP:
            if (msg->wParam == HTMAXBUTTON) {
                const bool was_pressed = max_pressed_;
                setMaxState(true, false);
                if (was_pressed) {
                    toggleMaximize();
                }
                if (result) {
                    *result = 0;
                }
                return true;
            }
            return false;
        default:
            return false;
    }
#else
    Q_UNUSED(eventType);
    Q_UNUSED(message);
    Q_UNUSED(result);
    return false;
#endif
}

} // namespace Intercli
