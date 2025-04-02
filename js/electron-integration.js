// electron-integration.js
// This module provides a compatibility layer between Electron and browser environments

// Check if running in Electron
const isElectron = () => {
    return window && window.electronAPI;
  };
  
  // Server management functions
  export const serverAPI = {
    startServer: async (port, folder) => {
      if (isElectron()) {
        return await window.electronAPI.server.start(port, folder);
      } else {
        console.warn('Server functions are only available in Electron environment');
        return { isRunning: false, error: 'Server functions are only available in Electron environment' };
      }
    },
  
    stopServer: async () => {
      if (isElectron()) {
        return await window.electronAPI.server.stop();
      } else {
        console.warn('Server functions are only available in Electron environment');
        return { isRunning: false, error: 'Server functions are only available in Electron environment' };
      }
    },
  
    getStatus: async () => {
      if (isElectron()) {
        return await window.electronAPI.server.getStatus();
      } else {
        console.warn('Server functions are only available in Electron environment');
        return { isRunning: false, error: 'Server functions are only available in Electron environment' };
      }
    }
  };
  
  // File management functions
  export const fileAPI = {
    selectFolder: async () => {
      if (isElectron()) {
        return await window.electronAPI.dialog.openFolder();
      } else {
        console.warn('File dialog functions are only available in Electron environment');
        return null;
      }
    },
  
    selectFile: async () => {
      if (isElectron()) {
        return await window.electronAPI.dialog.openFile();
      } else {
        console.warn('File dialog functions are only available in Electron environment');
        return null;
      }
    }
  };
  
  // Database management functions
  export const databaseAPI = {
    connect: async (dbPath) => {
      if (isElectron()) {
        return await window.electronAPI.database.connect(dbPath);
      } else {
        console.warn('Database functions are only available in Electron environment');
        return { isConnected: false, error: 'Database functions are only available in Electron environment' };
      }
    },
  
    disconnect: async () => {
      if (isElectron()) {
        return await window.electronAPI.database.disconnect();
      } else {
        console.warn('Database functions are only available in Electron environment');
        return { isConnected: false, error: 'Database functions are only available in Electron environment' };
      }
    },
  
    getStatus: async () => {
      if (isElectron()) {
        return await window.electronAPI.database.getStatus();
      } else {
        console.warn('Database functions are only available in Electron environment');
        return { isConnected: false, error: 'Database functions are only available in Electron environment' };
      }
    },
  
    selectDatabase: async () => {
      if (isElectron()) {
        return await window.electronAPI.openDatabaseDialog();
      } else {
        console.warn('Database functions are only available in Electron environment');
        return null;
      }
    }
  };
  
  // Auth functions - These work in both Electron and browser environments
  // but will use Electron-specific methods when available
  export const authAPI = {
    login: async (username, password) => {
      if (isElectron()) {
        return await window.electronAPI.auth.login(username, password);
      } else {
        // Use fetch API for browser environment
        const response = await fetch('/api/login', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ email: username, password })
        });
  
        if (!response.ok) {
          const errorData = await response.json();
          throw new Error(errorData.message || 'Login failed');
        }
  
        return await response.json();
      }
    },
  
    logout: () => {
      if (isElectron()) {
        return window.electronAPI.auth.logout();
      } else {
        // Clear auth token and redirect
        localStorage.removeItem('authToken');
        window.location.href = '/login.html';
      }
    },
  
    verifyToken: async (token) => {
      if (isElectron()) {
        return await window.electronAPI.auth.verifyToken(token);
      } else {
        // Use fetch API for token verification
        try {
          const response = await fetch('/api/user/profile', {
            headers: {
              'Authorization': `Bearer ${token}`
            }
          });
  
          if (!response.ok) {
            return { valid: false };
          }
  
          return { valid: true, user: await response.json() };
        } catch (error) {
          return { valid: false, error: error.message };
        }
      }
    }
  };
  
  // Event listeners for Electron events
  export const setupEventListeners = (callbacks = {}) => {
    if (!isElectron()) return {};
  
    const cleanupFunctions = {};
  
    if (callbacks.onServerStatus) {
      const cleanup = window.electronAPI.onServerStatus(callbacks.onServerStatus);
      cleanupFunctions.serverStatus = cleanup;
    }
  
    if (callbacks.onServerLog) {
      const cleanup = window.electronAPI.onServerLog(callbacks.onServerLog);
      cleanupFunctions.serverLog = cleanup;
    }
  
    if (callbacks.onFilesAdded) {
      const cleanup = window.electronAPI.onFilesAdded(callbacks.onFilesAdded);
      cleanupFunctions.filesAdded = cleanup;
    }
  
    if (callbacks.onDatabaseStatus) {
      const cleanup = window.electronAPI.onDatabaseStatus(callbacks.onDatabaseStatus);
      cleanupFunctions.databaseStatus = cleanup;
    }
  
    return {
      cleanup: () => {
        Object.values(cleanupFunctions).forEach(fn => fn && fn());
      }
    };
  };
  
  export default {
    isElectron,
    serverAPI,
    fileAPI,
    databaseAPI,
    authAPI,
    setupEventListeners
  };