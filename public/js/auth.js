// Authentication Service
export default class AuthService {
    // Get authentication token from local storage
    static getAuthToken() {
        return localStorage.getItem('authToken');
    }

    // Login with email and password
    static async loginUser(email, password) {
        try {
            const response = await fetch('/api/login', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ email, password })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                // Save token in localStorage
                localStorage.setItem('authToken', data.token);
                return data;
            } else {
                throw new Error(data.error || 'Login failed');
            }
        } catch (error) {
            console.error('Login error:', error);
            throw error;
        }
    }

    // Register new user
    static async register({ username, email, password }) {
        try {
            const response = await fetch('/api/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, email, password })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                return data;
            } else {
                throw new Error(data.error || 'Registration failed');
            }
        } catch (error) {
            console.error('Registration error:', error);
            throw error;
        }
    }

    // Google Login (placeholder - would need actual Google OAuth implementation)
    static async googleLogin() {
        alert('Google login not implemented');
        throw new Error('Google login not implemented');
    }

    // Logout
    static logout() {
        localStorage.removeItem('authToken');
        window.location.href = '/login.html';
    }
}

// Named exports for easier import in HTML files
export function loginUser(email, password) {
    return AuthService.loginUser(email, password);
}

export function loginWithGoogle() {
    return AuthService.googleLogin();
}

export function logout() {
    AuthService.logout();
}

export function getAuthToken() {
    return AuthService.getAuthToken();
}