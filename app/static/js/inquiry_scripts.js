// inquiry_scripts.js

document.addEventListener('DOMContentLoaded', function () {
    // Auto-hide flash messages after 5 seconds
    const flashMessages = document.querySelectorAll('.alert');
    if (flashMessages.length > 0) {
        setTimeout(() => {
            flashMessages.forEach(message => {
                message.classList.add('fade-out');
                setTimeout(() => {
                    message.remove();
                }, 500);
            });
        }, 5000);
    }

    // Add animation to inquiry rows
    const inquiryRows = document.querySelectorAll('.inquiry-row');
    inquiryRows.forEach((row, index) => {
        setTimeout(() => {
            row.classList.add('visible');
        }, index * 100);
    });

    // Textarea auto-resize (for reply form)
    const textareas = document.querySelectorAll('.auto-resize');
    textareas.forEach(textarea => {
        textarea.addEventListener('input', function () {
            this.style.height = 'auto';
            this.style.height = (this.scrollHeight) + 'px';
        });
    });

    // Message timestamp formatting
    const timestamps = document.querySelectorAll('.timestamp');
    timestamps.forEach(timestamp => {
        const dateString = timestamp.getAttribute('data-time');
        if (dateString) {
            const date = new Date(dateString);
            const now = new Date();

            // Format based on how recent the message is
            if (isSameDay(date, now)) {
                timestamp.textContent = 'Today at ' + formatTime(date);
            } else if (isYesterday(date, now)) {
                timestamp.textContent = 'Yesterday at ' + formatTime(date);
            } else {
                timestamp.textContent = formatDate(date);
            }
        }
    });
});

// Helper functions for date formatting
function isSameDay(date1, date2) {
    return date1.getDate() === date2.getDate() &&
        date1.getMonth() === date2.getMonth() &&
        date1.getFullYear() === date2.getFullYear();
}

function isYesterday(date1, date2) {
    const yesterday = new Date(date2);
    yesterday.setDate(yesterday.getDate() - 1);
    return date1.getDate() === yesterday.getDate() &&
        date1.getMonth() === yesterday.getMonth() &&
        date1.getFullYear() === yesterday.getFullYear();
}

function formatTime(date) {
    return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function formatDate(date) {
    return date.toLocaleDateString([], {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}