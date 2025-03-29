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
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

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

    // Password validation
    const passwordInput = document.getElementById('password');
    if (passwordInput) {
        const passwordMessage = document.getElementById('password-message');

        passwordInput.addEventListener('input', function () {
            const password = this.value;
            const parent = this.closest('.form-group');

            if (password.length < 8) {
                parent.classList.add('is-invalid');
                parent.classList.remove('is-valid');
                passwordMessage.textContent = 'Password must be at least 8 characters long';
            } else {
                parent.classList.remove('is-invalid');
                parent.classList.add('is-valid');
                passwordMessage.textContent = '';
            }

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

            let isValid = true;

            // Validate username
            if (username.length < 3 || !/^[a-zA-Z0-9_]+$/.test(username)) {
                document.getElementById('username').closest('.form-group').classList.add('is-invalid');
                document.getElementById('username-message').textContent = 'Username must be at least 3 characters and contain only letters, numbers, and underscores';
                isValid = false;
            }

            // Validate email
            const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
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
});