.pragma library

// Time labels in the style of Apple's Messages.

function sameDay(a, b) {
    return a.getFullYear() === b.getFullYear() && a.getMonth() === b.getMonth()
        && a.getDate() === b.getDate()
}

function daysBetween(a, b) {
    const da = new Date(a.getFullYear(), a.getMonth(), a.getDate())
    const db = new Date(b.getFullYear(), b.getMonth(), b.getDate())
    return Math.round((db - da) / 86400000)
}

function clock(d) {
    return Qt.formatTime(d, "h:mm")
}

// Sidebar row: "9:41", "Yesterday", "Mon", "15/11/26".
function rowTime(d) {
    if (!d || isNaN(d.getTime()))
        return ""
    const now = new Date()
    const days = daysBetween(d, now)
    if (days === 0) return clock(d)
    if (days === 1) return "Yesterday"
    if (days < 7) return Qt.formatDate(d, "ddd")
    return Qt.formatDate(d, "d/M/yy")
}

// Separator above a group of messages: "Today 9:36", "Yesterday 9:36", "Mon 9:36", "15 Nov 2026 9:36".
function separator(d) {
    if (!d || isNaN(d.getTime()))
        return ""
    const now = new Date()
    const days = daysBetween(d, now)
    if (days === 0) return "Today " + clock(d)
    if (days === 1) return "Yesterday " + clock(d)
    if (days < 7) return Qt.formatDate(d, "dddd") + " " + clock(d)
    return Qt.formatDate(d, "d MMM yyyy") + " " + clock(d)
}

// "Just now", "2 min ago", "1 hr ago", "Never".
function relative(d) {
    if (!d || isNaN(d.getTime()))
        return "Never"
    const secs = Math.max(0, (new Date() - d) / 1000)
    if (secs < 60) return "Just now"
    if (secs < 3600) return Math.floor(secs / 60) + " min ago"
    if (secs < 86400) return Math.floor(secs / 3600) + " hr ago"
    return Qt.formatDate(d, "d MMM")
}
