document.addEventListener('DOMContentLoaded', function () {
    // Elements
    const codeInput = document.getElementById('verification_code');
    const verifyForm = document.getElementById('verification-form');
    const resendForm = document.getElementById('resend-form');
    const resendButton = document.getElementById('resend-button');
    const verifyButton = document.getElementById('verify-button');
    const codeMessage = document.getElementById('code-message');
    const countdownElement = document.getElementById('countdown');

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
        showFlashMessage('error', 'Verification code has expired. Please request a new one.');
        resendButton.classList.remove('btn-disabled');
        verifyButton.classList.add('btn-disabled');
        codeInput.disabled = true;
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

    // Handle verification form submission
    if (verifyForm) {
        verifyForm.addEventListener('submit', function (e) {
            e.preventDefault();

            const code = codeInput.value.trim();

            if (code.length !== 6) {
                codeMessage.textContent = 'Please enter a valid 6-digit code';
                codeInput.parentElement.parentElement.classList.add('is-invalid');
                return;
            }

            // Show loading state
            verifyButton.classList.add('btn-loading');
            verifyButton.disabled = true;

            // Simulate verification process
            setTimeout(function () {
                // This would normally be handled by the server
                // For demonstration, we'll simulate success and redirect

                // Simulate success (in real implementation, this would be a fetch request)
                verifyEmail(code);
            }, 1500);
        });
    }

    // Handle resend code form submission
    if (resendForm) {
        resendForm.addEventListener('submit', function (e) {
            e.preventDefault();

            // Show loading state
            resendButton.classList.add('btn-loading');
            resendButton.disabled = true;

            // Simulate resend process
            setTimeout(function () {
                // Reset UI
                resendButton.classList.remove('btn-loading');
                resendButton.disabled = false;

                // Reset the verification code input
                codeInput.value = '';
                codeInput.classList.remove('is-valid');
                codeInput.disabled = false;

                // Show success message
                showFlashMessage('success', 'A new verification code has been sent to your email');

                // Reset the countdown timer
                startCountdown();

                // Re-enable verification button
                verifyButton.classList.remove('btn-disabled');
                verifyButton.disabled = false;
            }, 2000);
        });
    }

    // Function to handle email verification
    function verifyEmail(code) {
        // In a real implementation, this would be a fetch request to the server
        // For this demo, we'll simulate the verification process

        // Simulate server validation (in real implementation, this would be a fetch call)
        const isValid = true; // Simulated validation result

        if (isValid) {
            // Show success message
            showFlashMessage('success', 'Email verification successful!');

            // Add success animation to the form
            verifyForm.classList.add('verification-success');

            // Show verification success UI
            codeInput.classList.add('is-valid');
            verifyButton.classList.remove('btn-loading');
            verifyButton.innerHTML = `
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                    stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                    <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
                    <polyline points="22 4 12 14.01 9 11.01"></polyline>
                </svg>
                Verified Successfully
            `;

            // Redirect after a short delay (to show success state)
            setTimeout(function () {
                window.location.href = '/dashboard';
            }, 2000);
        } else {
            // Show error message
            showFlashMessage('error', 'Invalid verification code. Please try again.');

            // Reset UI
            verifyButton.classList.remove('btn-loading');
            verifyButton.disabled = false;
            codeInput.classList.remove('is-valid');
            codeInput.classList.add('is-invalid');
            codeInput.focus();
        }
    }

    // Function to display flash messages
    function showFlashMessage(type, message) {
        const flashContainer = document.getElementById('flash-messages');

        // Create message element
        const messageElement = document.createElement('div');
        messageElement.className = `flash-message ${type}`;

        // Create content wrapper for the message text
        const contentWrapper = document.createElement('span');
        contentWrapper.className = 'flash-content';
        contentWrapper.textContent = message;

        // Add icon based on message type
        const iconSvg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        iconSvg.setAttribute('viewBox', '0 0 24 24');
        iconSvg.setAttribute('fill', 'none');
        iconSvg.setAttribute('stroke', 'currentColor');
        iconSvg.setAttribute('stroke-width', '2');
        iconSvg.setAttribute('stroke-linecap', 'round');
        iconSvg.setAttribute('stroke-linejoin', 'round');

        let iconPath;

        if (type === 'success') {
            iconPath = '<polyline points="20 6 9 17 4 12"></polyline>';
        } else if (type === 'error') {
            iconPath = '<circle cx="12" cy="12" r="10"></circle><line x1="12" y1="8" x2="12" y2="12"></line><line x1="12" y1="16" x2="12.01" y2="16"></line>';
        } else {
            iconPath = '<circle cx="12" cy="12" r="10"></circle><line x1="12" y1="16" x2="12" y2="12"></line><line x1="12" y1="8" x2="12.01" y2="8"></line>';
        }

        iconSvg.innerHTML = iconPath;

        // Create close button
        const closeBtn = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
        closeBtn.setAttribute('viewBox', '0 0 24 24');
        closeBtn.setAttribute('fill', 'none');
        closeBtn.setAttribute('stroke', 'currentColor');
        closeBtn.setAttribute('stroke-width', '2');
        closeBtn.setAttribute('stroke-linecap', 'round');
        closeBtn.setAttribute('stroke-linejoin', 'round');
        closeBtn.setAttribute('class', 'close-btn');
        closeBtn.innerHTML = '<line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line>';

        // Close button click handler
        closeBtn.addEventListener('click', () => {
            messageElement.style.opacity = '0';
            setTimeout(() => {
                if (flashContainer.contains(messageElement)) {
                    flashContainer.removeChild(messageElement);
                }
            }, 300);
        });

        // Append elements in the correct order (icon, message, close button)
        messageElement.appendChild(iconSvg);
        messageElement.appendChild(contentWrapper);
        messageElement.appendChild(closeBtn);

        // Add message to container
        flashContainer.appendChild(messageElement);

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