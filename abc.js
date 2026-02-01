
        // 1. DOM XSS (No input sanitization)
        function updateGreeting() {
            const userInput = document.getElementById('user-input').value;
            // VULNERABILITY: Direct injection into DOM
            document.getElementById('user-greeting').innerHTML = 
                'Hello, ' + userInput + '!'; 
        }

        // 2. IDOR (Predictable resource access)
        function viewUser(userId) {
            // VULNERABILITY: No access control check
            fetch(`/api/users/${userId}`)
                .then(res => res.json())
                .then(data => console.log(data));
        }

        // 3. Client-Side Auth Bypass
        function showAdminPanel() {
            // VULNERABILITY: Authorization enforced only in UI
            document.getElementById('admin-panel').style.display = 'block';
        }

        // 4. Insecure Storage
        function saveCredentials(username, password) {
            // VULNERABILITY: Storing credentials in localStorage
            localStorage.setItem('username', username);
            localStorage.setItem('password', password); // NEVER DO THIS!
        }

        // 5. Prototype Pollution (Simulated)
        function merge(target, source) {
            // VULNERABILITY: Unsafe object merging
            for (const key in source) {
                if (key === '__proto__' || key === 'constructor') {
                    // Intentionally NOT protected
                }
                target[key] = source[key];
            }
            return target;
        }

        // 6. Insecure Randomness
        function generateToken() {
            // VULNERABILITY: Math.random() is not cryptographically secure
            return Math.random().toString(36).substring(2, 15);
        }

        // 7. Open Redirect
        function redirect(url) {
            // VULNERABILITY: Unvalidated redirect
            window.location.href = url;
        }

        // Example usage of vulnerable functions
        // saveCredentials('admin', 'supersecret');
        // redirect('https://evil.com');
