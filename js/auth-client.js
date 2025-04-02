// js/auth-client.js - Updated for database integration
import * as crypto from 'node:crypto';
import dotenv from 'dotenv';
import AUTH_CONFIG from './auth-config.js';

dotenv.config();

// Check if we have a DatabaseManager instance
let dbManager = null;

// Try to connect to the database
try {
  const getDatabaseManager = () => {
    // In Electron context
    if (typeof window !== 'undefined' && window.electronAPI) {
      return window.electronAPI.database.getStatus()
        .then(status => {
          if (status.isConnected) {
            return true;
          }
          return false;
        });
    }
    // In Node.js context
    else if (typeof global !== 'undefined' && global.dbManager) {
      return Promise.resolve(global.dbManager);
    }
    return Promise.resolve(false);
  };

  // Set up database connection when module is loaded
  getDatabaseManager().then(manager => {
    dbManager = manager;
    console.log('Authentication client using database manager');
  }).catch(err => {
    console.warn('Could not get database manager, using in-memory storage:', err);
  });
} catch (e) {
  console.warn('Error initializing database connection:', e);
}

// In-memory storage as fallback
const users = new Map();

// Encryption functions
function encryptData(data, secretKey) {
    const cipher = crypto.createCipheriv('aes-256-cbc', 
        Buffer.from(secretKey, 'hex').slice(0, 32), 
        Buffer.from(secretKey.slice(32, 64), 'hex')
    );
    let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

function decryptData(encryptedData, secretKey) {
    const decipher = crypto.createDecipheriv('aes-256-cbc', 
        Buffer.from(secretKey, 'hex').slice(0, 32), 
        Buffer.from(secretKey.slice(32, 64), 'hex')
    );
    let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return JSON.parse(decrypted);
}

// Backend functions
export async function registerUserBackend(username, email, password) {
    // Try to use database if available
    if (dbManager) {
        try {
            // Format data for database
            const userData = {
                username,
                email,
                password,
                authProvider: 'local'
            };
            
            // Create user in database
            const user = await dbManager.createUser(userData);
            return user.id;
        } catch (error) {
            console.error('Database user registration error:', error);
            // Fall back to in-memory if database fails
        }
    }
    
    // Fall back to in-memory storage
    // Check if user already exists
    if (users.has(email)) {
        throw new Error('User with this email already exists');
    }

    // Generate a unique encryption key for this user
    const userEncryptionKey = crypto.randomBytes(64).toString('hex');

    // Hash password with a salt
    const salt = crypto.randomBytes(16).toString('hex');
    const hashedPassword = crypto.pbkdf2Sync(
        password, 
        salt, 
        1000, 
        64, 
        'sha512'
    ).toString('hex');

    // Prepare encrypted user data
    const userData = {
        username,
        email,
        salt,
        hashedPassword
    };

    // Encrypt the entire user data
    const encryptedUserData = encryptData(userData, userEncryptionKey);

    // Store encrypted data and encryption key in memory
    const userId = crypto.randomUUID();
    users.set(email, {
        id: userId,
        email,
        encryptedData: encryptedUserData,
        encryptionKeyHash: crypto.createHash('sha256').update(userEncryptionKey).digest('hex'),
        encryptionKey: userEncryptionKey // In a real app, we wouldn't store this here
    });

    return userId;
}

export async function loginUserBackend(email, password) {
    // Try to use database if available
    if (dbManager) {
        try {
            const user = await dbManager.getUserByEmail(email);
            if (!user) {
                throw new Error('User not found');
            }
            
            // Verify password (handled by AuthService in the database version)
            // Import bcrypt if needed
            const bcrypt = await import('bcryptjs');
            const isMatch = await bcrypt.compare(password, user.password_hash);
            
            // Continuing from where we left off in auth-client.js
            if (!isMatch) {
                throw new Error('Invalid email or password');
            }
            
            // Update last login time
            await dbManager.updateUserLogin(user.id);
            
            // Generate token using JWT in a real app
            // For simplicity, we'll use a similar method to our in-memory version
            const token = generateToken({
                id: user.id,
                email: user.email,
                username: user.username
            });
            
            // Store session in database
            await dbManager.createSession(user.id, token);
            
            return token;
        } catch (error) {
            console.error('Database login error:', error);
            // Fall back to in-memory if database fails
        }
    }

    // Fall back to in-memory storage
    // Find user by email
    const userRecord = users.get(email);
    if (!userRecord) {
        throw new Error('User not found');
    }

    // Try to decrypt user data
    let userData;
    try {
        // Use the stored encryption key (in a real app this would be more secure)
        const userEncryptionKey = userRecord.encryptionKey;
        
        userData = decryptData(userRecord.encryptedData, userEncryptionKey);
    } catch (error) {
        throw new Error('Error decrypting data');
    }

    // Verify password
    const hashedInputPassword = crypto.pbkdf2Sync(
        password, 
        userData.salt, 
        1000, 
        64, 
        'sha512'
    ).toString('hex');
    
    if (hashedInputPassword !== userData.hashedPassword) {
        throw new Error('Invalid password');
    }

    // Generate JWT or session token
    const token = generateToken(userData);
    return token;
}

export async function loginWithGoogleBackend(googleProfile) {
    // Try to use database if available
    if (dbManager) {
        try {
            // Check if user exists by Google ID
            let user = await dbManager.getUserByProviderAuthId('google', googleProfile.sub);
            
            if (!user) {
                // Check if user exists by email
                user = await dbManager.getUserByEmail(googleProfile.email);
                
                if (!user) {
                    // Create new user
                    user = await dbManager.createUser({
                        username: googleProfile.name || googleProfile.email.split('@')[0],
                        email: googleProfile.email,
                        authProvider: 'google',
                        authProviderId: googleProfile.sub
                    });
                } else {
                    // User exists but doesn't have Google authentication
                    // This would need careful handling in a real app
                    console.warn('User exists with different auth method');
                }
            }
            
            // Update last login time
            await dbManager.updateUserLogin(user.id);
            
            // Generate token
            const token = generateToken({
                id: user.id,
                email: user.email,
                username: user.username
            });
            
            // Store session
            await dbManager.createSession(user.id, token);
            
            return token;
        } catch (error) {
            console.error('Database Google login error:', error);
            // Fall back to in-memory if database fails
        }
    }

    // Check if user already exists
    let userRecord = users.get(googleProfile.email);

    if (!userRecord) {
        // Generate a unique encryption key for this user
        const userEncryptionKey = crypto.randomBytes(64).toString('hex');

        // User data
        const userData = {
            username: googleProfile.name || googleProfile.email.split('@')[0],
            email: googleProfile.email,
            googleId: googleProfile.sub,
            avatar: googleProfile.picture || null
        };

        // Encrypt user data
        const encryptedUserData = encryptData(userData, userEncryptionKey);

        // Save to memory
        const userId = crypto.randomUUID();
        users.set(googleProfile.email, {
            id: userId,
            email: googleProfile.email,
            encryptedData: encryptedUserData,
            encryptionKeyHash: crypto.createHash('sha256').update(userEncryptionKey).digest('hex'),
            encryptionKey: userEncryptionKey
        });
        
        userRecord = users.get(googleProfile.email);
    }

    // Decrypt user data
    const userEncryptionKey = userRecord.encryptionKey;
    const userData = decryptData(userRecord.encryptedData, userEncryptionKey);

    // Generate token
    return generateToken(userData);
}

// Token Generation
function generateToken(userData) {
    // In a production environment, use a proper JWT library
    const payload = {
        id: userData.id,
        email: userData.email,
        username: userData.username,
        timestamp: Date.now()
    };

    // Simple token generation
    return Buffer.from(JSON.stringify(payload)).toString('base64');
}

export async function verifyToken(token) {
    // Try to use database if available
    if (dbManager) {
        try {
            // Check if token exists in sessions table
            const session = await dbManager.getSessionByToken(token);
            
            if (!session) {
                throw new Error('Invalid token or session expired');
            }
            
            // Get user data
            const user = await dbManager.getUserById(session.user_id);
            
            if (!user) {
                throw new Error('User not found');
            }
            
            // Return user data
            return {
                id: user.id,
                email: user.email,
                username: user.username
            };
        } catch (error) {
            console.error('Database token verification error:', error);
            // Fall back to in-memory if database fails
        }
    }

    try {
        const payload = JSON.parse(Buffer.from(token, 'base64').toString('utf-8'));
        
        // Additional verification can be added here
        // For example, check token expiration, validate against database, etc.
        
        return payload;
    } catch (error) {
        throw new Error('Invalid token');
    }
}

// Client-side functions that work with the backend
export async function registerUser(username, email, password) {
    try {
        const response = await fetch(AUTH_CONFIG.endpoints.register, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, email, password })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || 'Registration error');
        }

        const data = await response.json();
        return data.userId;
    } catch (error) {
        console.error('Registration error:', error);
        throw error;
    }
}

export async function loginUser(email, password) {
    try {
        const response = await fetch(AUTH_CONFIG.endpoints.login, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, password })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || 'Login error');
        }

        const data = await response.json();
        // Save token in localStorage
        localStorage.setItem(AUTH_CONFIG.jwt.tokenName, data.token);
        return data.token;
    } catch (error) {
        console.error('Login error:', error);
        throw error;
    }
}

export function loginWithGoogle() {
    // Redirect to Google auth endpoint
    window.location.href = AUTH_CONFIG.endpoints.googleAuth;
}

export function logout() {
    localStorage.removeItem(AUTH_CONFIG.jwt.tokenName);
    window.location.href = AUTH_CONFIG.redirects.afterLogout;
}

export function isLoggedIn() {
    return !!localStorage.getItem(AUTH_CONFIG.jwt.tokenName);
}

export function getAuthToken() {
    return localStorage.getItem(AUTH_CONFIG.jwt.tokenName);
}

// Export for use in browser environments
export const authClient = {
    registerUser,
    loginUser,
    loginWithGoogle,
    logout,
    isLoggedIn,
    getAuthToken
};