#pragma once

#include <QAbstractNativeEventFilter>
#include <QObject>
#include <QRectF>

class QQuickWindow;

namespace Intercli {

// Lets the app draw its own title bar while Windows keeps treating it as a normal
// window: snap, Win+arrow, the snap-layout flyout on the maximise button, edge
// resizing, the shadow and rounded corners. QML tells it where the drag area and
// caption buttons are. On other platforms customFrame is false and the system
// frame is used.
class WindowsFrame : public QObject, public QAbstractNativeEventFilter {
    Q_OBJECT
    Q_PROPERTY(bool customFrame READ customFrame CONSTANT)
    Q_PROPERTY(bool micaActive READ micaActive NOTIFY micaActiveChanged)
    Q_PROPERTY(bool maximized READ maximized NOTIFY maximizedChanged)
    Q_PROPERTY(bool maxHovered READ maxHovered NOTIFY maxButtonChanged)
    Q_PROPERTY(bool maxPressed READ maxPressed NOTIFY maxButtonChanged)

public:
    explicit WindowsFrame(QObject* parent = nullptr);
    ~WindowsFrame() override;

    // Call once the window exists (after the QML engine loaded it).
    void attach(QQuickWindow* window);

    bool customFrame() const;
    bool micaActive() const { return mica_active_; }
    bool maximized() const { return maximized_; }
    bool maxHovered() const { return max_hovered_; }
    bool maxPressed() const { return max_pressed_; }

    // Window-local logical pixels.
    Q_INVOKABLE void setCaptionRects(const QRectF& dragArea, const QRectF& minButton, const QRectF& maxButton,
                                     const QRectF& closeButton);
    Q_INVOKABLE void minimize();
    Q_INVOKABLE void toggleMaximize();
    Q_INVOKABLE void close();

    bool nativeEventFilter(const QByteArray& eventType, void* message, qintptr* result) override;

signals:
    void micaActiveChanged();
    void maximizedChanged();
    void maxButtonChanged();

private:
    void setMaxState(bool hovered, bool pressed);
    void updateMaximized();
    void fixRestoreRect();

    QQuickWindow* window_ = nullptr;
    quintptr hwnd_ = 0;
    QRectF drag_;
    QRectF min_;
    QRectF max_;
    QRectF close_;
    bool mica_active_ = false;
    bool maximized_ = false;
    bool max_hovered_ = false;
    bool max_pressed_ = false;
    bool tracking_nc_leave_ = false;
    // Last restore rectangle seen while the window was not maximised (workspace coordinates).
    bool has_normal_ = false;
    long normal_left_ = 0;
    long normal_top_ = 0;
    long normal_right_ = 0;
    long normal_bottom_ = 0;
};

} // namespace Intercli
