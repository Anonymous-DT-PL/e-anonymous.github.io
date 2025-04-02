// auth.js - Combined backend and frontend authentication

import * as crypto from 'node:crypto';
import dotenv from 'dotenv';

dotenv.config();

// In-memory storage instead of MongoDB
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
    // Check if user already exists
    if (users.has(email)) {
        throw new Error('Użytkownik o tym adresie email już istnieje');
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
    // Find user by email
    const userRecord = users.get(email);
    if (!userRecord) {
        throw new Error('Użytkownik nie został znaleziony');
    }

    // Try to decrypt user data
    let userData;
    try {
        // Use the stored encryption key (in a real app this would be more secure)
        const userEncryptionKey = userRecord.encryptionKey;
        
        userData = decryptData(userRecord.encryptedData, userEncryptionKey);
    } catch (error) {
        throw new Error('Błąd podczas deszyfrowania danych');
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
        throw new Error('Nieprawidłowe hasło');
    }

    // Generate JWT or session token
    const token = generateToken(userData);
    return token;
}

export async function loginWithGoogleBackend(googleProfile) {
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
        email: userData.email,
        username: userData.username,
        timestamp: Date.now()
    };

    // Simple token generation
    return Buffer.from(JSON.stringify(payload)).toString('base64');
}

export async function verifyToken(token) {
    try {
        const payload = JSON.parse(Buffer.from(token, 'base64').toString('utf-8'));
        
        // Additional verification can be added here
        // For example, check token expiration, validate against database, etc.
        
        return payload;
    } catch (error) {
        throw new Error('Nieprawidłowy token');
    }
}

// Client-side functions that work with the backend
export async function registerUser(username, email, password) {
    try {
        const response = await fetch('/api/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, email, password })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || 'Błąd rejestracji');
        }

        const data = await response.json();
        return data.userId;
    } catch (error) {
        console.error('Błąd rejestracji:', error);
        throw error;
    }
}

export async function loginUser(email, password) {
    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, password })
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.message || 'Błąd logowania');
        }

        const data = await response.json();
        // Zapisz token w localStorage
        localStorage.setItem('authToken', data.token);
        return data.token;
    } catch (error) {
        console.error('Błąd logowania:', error);
        throw error;
    }
}

export function loginWithGoogle() {
    // Przekieruj do endpointu logowania Google
    window.location.href = '/login/google';
}

export function logout() {
    localStorage.removeItem('authToken');
    window.location.href = '/login.html';
}

export function isLoggedIn() {
    return !!localStorage.getItem('authToken');
}

export function getAuthToken() {
    return localStorage.getItem('authToken');
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