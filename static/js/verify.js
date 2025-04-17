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
        const closeBtn = messageElement.querySelector('.close-btn');
        closeBtn.addEventListener('click', () => {
            messageElement.style.opacity = '0';
            setTimeout(() => {
                if (flashContainer.contains(messageElement)) {
                    flashContainer.removeChild(messageElement);
                }
            }, 300);
        });

        // Auto-dismiss after 4 seconds
        setTimeout(() => {
            messageElement.style.opacity = '0';
            setTimeout(() => {
                if (flashContainer.contains(messageElement)) {
                    flashContainer.removeChild(messageElement);
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
            }
        });
    }

    // Handle verification form submission - let server handle everything
    if (verifyForm) {
        verifyForm.addEventListener('submit', function () {
            // Show loading state on button during form submission
            const verifyButton = document.getElementById('verify-button');
            verifyButton.classList.add('btn-loading');

            // Don't need to prevent default - let the form submit normally
            // The server will handle verification and redirection
        });
    }

    // Handle resend code form - let server handle everything
    if (resendForm) {
        resendForm.addEventListener('submit', function () {
            // Show loading state on button during form submission
            const resendButton = document.getElementById('resend-button');
            resendButton.classList.add('btn-loading');
            resendButton.disabled = true;

            // Don't need to prevent default - let the form submit normally
            // The server will handle resending the code
        });
    }

    // Check if we have server-side flash messages to display
    const serverFlashMessages = document.querySelectorAll('.flash-message');
    serverFlashMessages.forEach(message => {
        // Add close button functionality to server-generated flash messages
        const closeBtn = message.querySelector('.close-btn');
        if (closeBtn) {
            closeBtn.addEventListener('click', () => {
                message.style.opacity = '0';
                setTimeout(() => {
                    if (message.parentElement.contains(message)) {
                        message.parentElement.removeChild(message);
                    }
                }, 300);
            });
        }

        // Auto-dismiss after 4 seconds
        setTimeout(() => {
            message.style.opacity = '0';
            setTimeout(() => {
                if (message.parentElement && message.parentElement.contains(message)) {
                    message.parentElement.removeChild(message);
                }
            }, 300);
        }, 4000);
    });

    // Alternative OTP input visualization (optional enhancement)
    function createOtpDigitDisplay() {
        const otpContainer = document.createElement('div');
        otpContainer.className = 'otp-digits';

        // Create 6 digit boxes
        for (let i = 0; i < 6; i++) {
            const digitBox = document.createElement('div');
            digitBox.className = 'otp-digit';
            digitBox.setAttribute('data-index', i);
            otpContainer.appendChild(digitBox);
        }

        // Insert after the input
        const inputWrapper = codeInput.parentElement;
        inputWrapper.parentNode.insertBefore(otpContainer, inputWrapper.nextSibling);

        // Update the digit display when input changes
        codeInput.addEventListener('input', function () {
            const digits = document.querySelectorAll('.otp-digit');
            const value = this.value;

            digits.forEach((digit, index) => {
                if (index < value.length) {
                    digit.textContent = value[index];
                    digit.classList.add('filled');
                } else {
                    digit.textContent = '';
                    digit.classList.remove('filled');
                }

                digit.classList.remove('active');
                if (index === value.length) {
                    digit.classList.add('active');
                }
            });
        });

        // Handle clicks on digit boxes to focus the input
        otpContainer.addEventListener('click', function () {
            codeInput.focus();
        });
    }

    // Uncomment to enable the visual OTP digit display
    // createOtpDigitDisplay();
});