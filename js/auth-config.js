// auth-config.js
// Central authentication configuration to unify all auth methods

export const AUTH_CONFIG = {
    // JWT configuration
    jwt: {
      tokenName: 'authToken',
      expiresIn: '24h',
    },
    
    // API endpoints
    endpoints: {
      register: '/api/register',
      login: '/api/login',
      logout: '/api/logout',
      googleAuth: '/login/google',
      googleCallback: '/auth/google/callback',
      dashboard: '/api/dashboard',
      commands: '/api/commands',
      stats: '/api/stats'
    },
    
    // Default redirect paths
    redirects: {
      afterLogin: '/dashboard.html',
      afterLogout: '/login.html',
      afterRegister: '/dashboard.html',
      unauthorized: '/login.html'
    }
  };
  
  // Helper functions for authentication
  export function saveAuthToken(token) {
    localStorage.setItem(AUTH_CONFIG.jwt.tokenName, token);
  }
  
  export function getAuthToken() {
    return localStorage.getItem(AUTH_CONFIG.jwt.tokenName);
  }
  
  export function removeAuthToken() {
    localStorage.removeItem(AUTH_CONFIG.jwt.tokenName);
  }
  
  export function isLoggedIn() {
    return !!getAuthToken();
  }
  
  export function logout() {
    removeAuthToken();
    window.location.href = AUTH_CONFIG.redirects.afterLogout;
  }
  
  export function redirectToLogin() {
    window.location.href = AUTH_CONFIG.redirects.unauthorized;
  }
  
  export default AUTH_CONFIG;