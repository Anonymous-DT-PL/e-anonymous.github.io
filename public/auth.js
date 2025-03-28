import crypto from 'crypto';
import { MongoClient } from 'mongodb';
import dotenv from 'dotenv';

dotenv.config();

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

// Database connection
async function connectToDatabase() {
    const client = new MongoClient(process.env.MONGODB_URI);
    await client.connect();
    return client.db(process.env.DB_NAME);
}

// User registration
export async function registerUser(username, email, password) {
    const db = await connectToDatabase();
    const usersCollection = db.collection('users');

    // Check if user already exists
    const existingUser = await usersCollection.findOne({ email });
    if (existingUser) {
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

    // Store encrypted data and encryption key separately
    const result = await usersCollection.insertOne({
        email,
        encryptedData: encryptedUserData,
        encryptionKeyHash: crypto.createHash('sha256').update(userEncryptionKey).digest('hex')
    });

    return result.insertedId;
}

// User login
export async function loginUser(email, password) {
    const db = await connectToDatabase();
    const usersCollection = db.collection('users');

    // Find user by email
    const userRecord = await usersCollection.findOne({ email });
    if (!userRecord) {
        throw new Error('Użytkownik nie został znaleziony');
    }

    // Try to decrypt user data
    let userData;
    try {
        // In a real-world scenario, you would securely manage and retrieve the encryption key
        // This is a simplified example
        const userEncryptionKey = process.env.MASTER_ENCRYPTION_KEY;
        
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

// Token Verification
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