document.addEventListener('DOMContentLoaded', function () {
    // Auto-hide flash messages after 5 seconds
    const flashMessages = document.querySelectorAll('.flash-message');
    if (flashMessages.length > 0) {
        setTimeout(function () {
            flashMessages.forEach(function (message) {
                message.style.opacity = '0';
                message.style.transition = 'opacity 0.5s ease';

                // Remove from DOM after fade out
                setTimeout(function () {
                    message.remove();
                }, 500);
            });
        }, 5000);
    }

    // Password visibility toggle
    const passwordToggles = document.querySelectorAll('.password-toggle');
    passwordToggles.forEach(function (toggle) {
        toggle.addEventListener('click', function () {
            const passwordInput = this.parentElement.querySelector('input');
            const eyeIcon = this.querySelector('.eye-icon');
            const eyeOffIcon = this.querySelector('.eye-off-icon');

            if (passwordInput.type === 'password') {
                passwordInput.type = 'text';
                eyeIcon.style.display = 'none';
                eyeOffIcon.style.display = 'block';
            } else {
                passwordInput.type = 'password';
                eyeIcon.style.display = 'block';
                eyeOffIcon.style.display = 'none';
            }
        });
    });

    // Username validation
    const usernameInput = document.getElementById('username');
    if (usernameInput) {
        const usernameValidation = document.getElementById('username-validation');
        const usernameMessage = document.getElementById('username-message');

        usernameInput.addEventListener('input', function () {
            const username = this.value.trim();
            const parent = this.closest('.form-group');

            if (username.length < 3) {
                parent.classList.add('is-invalid');
                parent.classList.remove('is-valid');
                usernameMessage.textContent = 'Username must be at least 3 characters long';
            } else if (!/^[a-zA-Z0-9_]+$/.test(username)) {
                parent.classList.add('is-invalid');
                parent.classList.remove('is-valid');
                usernameMessage.textContent = 'Username can only contain letters, numbers, and underscores';
            } else {
                parent.classList.remove('is-invalid');
                parent.classList.add('is-valid');
                usernameMessage.textContent = '';
            }
        });
    }

    // Email validation
    const emailInput = document.getElementById('email');
    if (emailInput) {
        const emailValidation = document.getElementById('email-validation');
        const emailMessage = document.getElementById('email-message');

        emailInput.addEventListener('input', function () {
            const email = this.value.trim();
            const parent = this.closest('.form-group');
            const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;

            if (!emailRegex.test(email)) {
                parent.classList.add('is-invalid');
                parent.classList.remove('is-valid');
                emailMessage.textContent = 'Please enter a valid email address';
            } else {
                parent.classList.remove('is-invalid');
                parent.classList.add('is-valid');
                emailMessage.textContent = '';
            }
        });
    }

    // Password validation and strength meter
    const passwordInput = document.getElementById('password');
    if (passwordInput) {
        const passwordMessage = document.getElementById('password-message');
        const strengthSegments = document.querySelectorAll('.strength-segment');

        passwordInput.addEventListener('input', function () {
            const password = this.value;
            const parent = this.closest('.form-group');

            // Basic validation
            if (password.length < 8) {
                parent.classList.add('is-invalid');
                parent.classList.remove('is-valid');
                passwordMessage.textContent = 'Password must be at least 8 characters long';
            } else {
                parent.classList.remove('is-invalid');
                parent.classList.add('is-valid');
                passwordMessage.textContent = '';
            }

            // Password strength calculation
            let strength = 0;

            // Length check
            if (password.length >= 8) strength += 1;
            if (password.length >= 12) strength += 1;

            // Complexity checks
            if (/[A-Z]/.test(password)) strength += 1; // Uppercase
            if (/[a-z]/.test(password)) strength += 1; // Lowercase
            if (/[0-9]/.test(password)) strength += 1; // Numbers
            if (/[^A-Za-z0-9]/.test(password)) strength += 1; // Special chars

            // Normalize to 0-4 scale
            strength = Math.min(Math.floor(strength / 1.5), 4);

            // Update strength meter
            const colors = ['#e0e0e0', '#f44336', '#ff9800', '#ffc107', '#4caf50'];
            strengthSegments.forEach((segment, index) => {
                if (index < strength) {
                    segment.style.backgroundColor = colors[strength];
                } else {
                    segment.style.backgroundColor = '#e0e0e0';
                }
            });

            // Update confirm password validation if exists
            const confirmPassword = document.getElementById('confirm_password');
            if (confirmPassword && confirmPassword.value) {
                confirmPassword.dispatchEvent(new Event('input'));
            }
        });
    }

    // Confirm password validation
    const confirmPasswordInput = document.getElementById('confirm_password');
    if (confirmPasswordInput) {
        const passwordMatchMessage = document.getElementById('password-match-message');

        confirmPasswordInput.addEventListener('input', function () {
            const confirmPassword = this.value;
            const password = document.getElementById('password').value;
            const parent = this.closest('.form-group');

            if (confirmPassword !== password) {
                parent.classList.add('is-invalid');
                parent.classList.remove('is-valid');
                passwordMatchMessage.textContent = 'Passwords do not match';
            } else {
                parent.classList.remove('is-invalid');
                parent.classList.add('is-valid');
                passwordMatchMessage.textContent = '';
            }
        });
    }

    // Form validation on submit
    const signupForm = document.querySelector('form[action="/signup"]');
    if (signupForm) {
        signupForm.addEventListener('submit', function (event) {
            const username = document.getElementById('username').value.trim();
            const email = document.getElementById('email').value.trim();
            const password = document.getElementById('password').value;
            const confirmPassword = document.getElementById('confirm_password').value;
            const termsCheckbox = document.getElementById('terms');

            let isValid = true;

            // Validate username
            if (username.length < 3 || !/^[a-zA-Z0-9_]+$/.test(username)) {
                document.getElementById('username').closest('.form-group').classList.add('is-invalid');
                document.getElementById('username-message').textContent = 'Username must be at least 3 characters and contain only letters, numbers, and underscores';
                isValid = false;
            }

            // Validate email
            const emailRegex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/;
            if (!emailRegex.test(email)) {
                document.getElementById('email').closest('.form-group').classList.add('is-invalid');
                document.getElementById('email-message').textContent = 'Please enter a valid email address';
                isValid = false;
            }

            // Validate password
            if (password.length < 8) {
                document.getElementById('password').closest('.form-group').classList.add('is-invalid');
                document.getElementById('password-message').textContent = 'Password must be at least 8 characters long';
                isValid = false;
            }

            // Validate confirm password
            if (password !== confirmPassword) {
                document.getElementById('confirm_password').closest('.form-group').classList.add('is-invalid');
                document.getElementById('password-match-message').textContent = 'Passwords do not match';
                isValid = false;
            }

            // Validate terms
            if (termsCheckbox && !termsCheckbox.checked) {
                isValid = false;
                // Add visual feedback for terms checkbox
                termsCheckbox.parentElement.classList.add('is-invalid');
            }

            if (!isValid) {
                event.preventDefault();
            }
        });
    }

    // Login form validation
    const loginForm = document.querySelector('form[action="/login"]');
    if (loginForm) {
        loginForm.addEventListener('submit', function (event) {
            const username = document.getElementById('username').value.trim();
            const password = document.getElementById('password').value;

            let isValid = true;

            // Validate username
            if (username.length === 0) {
                document.getElementById('username').closest('.form-group').classList.add('is-invalid');
                document.getElementById('username-message').textContent = 'Please enter your username';
                isValid = false;
            }

            // Validate password
            if (password.length === 0) {
                document.getElementById('password').closest('.form-group').classList.add('is-invalid');
                isValid = false;
            }

            if (!isValid) {
                event.preventDefault();
            }
        });
    }

    // Update Google button SVG to use correct logo
    const googleButtons = document.querySelectorAll('.btn-social.google svg');
    googleButtons.forEach(function (svg) {
        svg.innerHTML = `
            <g transform="matrix(1, 0, 0, 1, 0, 0)">
                <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
                <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
                <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
                <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
            </g>
        `;
    });
});