document.addEventListener('DOMContentLoaded', function () {
    // Elements
    const codeInput = document.getElementById('verification_code');
    const verifyForm = document.getElementById('verification-form');
    const resendForm = document.getElementById('resend-form');
    const countdownElement = document.getElementById('countdown');
    const codeMessage = document.getElementById('code-message');

    // Initialize verification timer
    let countdownTime = 5 * 60; // 5 minutes in seconds
    let countdownInterval;

    // Start countdown timer
    function startCountdown() {
        // Clear any existing countdown
        if (countdownInterval) {
            clearInterval(countdownInterval);
        }

        // Set initial countdown value
        countdownTime = 5 * 60;
        updateCountdownDisplay();

        // Start the countdown
        countdownInterval = setInterval(function () {
            countdownTime--;
            updateCountdownDisplay();

            if (countdownTime <= 0) {
                clearInterval(countdownInterval);
                showCodeExpired();
            }
        }, 1000);
    }

    // Update countdown display
    function updateCountdownDisplay() {
        const minutes = Math.floor(countdownTime / 60);
        const seconds = countdownTime % 60;
        countdownElement.textContent = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;

        // Change color when less than 1 minute remains
        if (countdownTime < 60) {
            countdownElement.style.color = '#f44336';
        } else {
            countdownElement.style.color = '';
        }
    }

    // Show code expired message
    function showCodeExpired() {
        // Add a flash message to indicate code expiration
        const flashContainer = document.getElementById('flash-messages');
        const messageElement = document.createElement('div');
        messageElement.className = 'flash-message error';
        messageElement.innerHTML = `
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" 
                stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="12" y1="8" x2="12" y2="12"></line>
                <line x1="12" y1="16" x2="12.01" y2="16"></line>
            </svg>
            <span class="flash-content">Verification code has expired. Please request a new one.</span>
            <svg class="close-btn" viewBox="0 0 24 24" fill="none" stroke="currentColor" 
                stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <line x1="18" y1="6" x2="6" y2="18"></line>
                <line x1="6" y1="6" x2="18" y2="18"></line>
            </svg>
        `;

        flashContainer.appendChild(messageElement);

        // Disable the verify button and input
        const verifyButton = document.getElementById('verify-button');
        verifyButton.disabled = true;
        verifyButton.classList.add('btn-disabled');
        codeInput.disabled = true;

        // Add click handler for the close button
        addFlashMessageHandlers(messageElement);
    }

    // Helper function to add dismiss handlers to flash messages
    function addFlashMessageHandlers(messageElement) {
        const closeBtn = messageElement.querySelector('.close-btn');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => {
                messageElement.style.opacity = '0';
                setTimeout(() => {
                    if (messageElement.parentElement && messageElement.parentElement.contains(messageElement)) {
                        messageElement.parentElement.removeChild(messageElement);
                    }
                }, 300);
            });
        }

        // Auto-dismiss after 4 seconds
        setTimeout(() => {
            messageElement.style.opacity = '0';
            setTimeout(() => {
                if (messageElement.parentElement && messageElement.parentElement.contains(messageElement)) {
                    messageElement.parentElement.removeChild(messageElement);
                }
            }, 300);
        }, 4000);
    }

    // Focus on verification code input
    if (codeInput) {
        codeInput.focus();

        // Start countdown on page load
        startCountdown();

        // Input handling for verification code
        codeInput.addEventListener('input', function () {
            // Remove non-numeric characters
            this.value = this.value.replace(/[^0-9]/g, '');

            // Clear any error messages on input
            codeMessage.textContent = '';
            codeMessage.parentElement.classList.remove('is-invalid');

            // Input validation
            if (this.value.length > 0 && this.value.length < 6) {
                codeMessage.textContent = 'Please enter all 6 digits';
            } else if (this.value.length === 6) {
                codeMessage.textContent = '';
                this.classList.add('is-valid');

                // Auto-submit the form when 6 digits are entered
                verifyForm.submit();
            }
        });
    }

    // Handle verification form submission - let server handle everything
    if (verifyForm) {
        verifyForm.addEventListener('submit', function () {
            // Show loading state on button during form submission
            const verifyButton = document.getElementById('verify-button');
            verifyButton.classList.add('btn-loading');
            // Let the form submit normally - server will handle verification
        });
    }

    // Handle resend code form submission - let server handle everything
    if (resendForm) {
        resendForm.addEventListener('submit', function (e) {
            // Show loading state on button during form submission
            const resendButton = document.getElementById('resend-button');
            resendButton.classList.add('btn-loading');

            // Ensure the action URL is correct
            resendForm.action = "/resend-code";  // Make sure this matches the app.py route

            // Let the form submit normally - server will handle resending and flashing messages
        });
    }

    // Check if we have server-side flash messages to display
    const serverFlashMessages = document.querySelectorAll('.flash-message');
    serverFlashMessages.forEach(message => {
        addFlashMessageHandlers(message);
    });
});