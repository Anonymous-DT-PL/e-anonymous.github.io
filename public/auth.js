import crypto from 'crypto';
import { MongoClient } from 'mongodb';
import dotenv from 'dotenv';

dotenv.config();

// Encryption functions
function encryptData(data, secretKey) {
    const cipher = crypto.createCipher('aes-256-cbc', secretKey);
    let encrypted = cipher.update(JSON.stringify(data), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    return encrypted;
}

function decryptData(encryptedData, secretKey) {
    const decipher = crypto.createDecipher('aes-256-cbc', secretKey);
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

    // Hash password
    const salt = crypto.randomBytes(16).toString('hex');
    const hashedPassword = crypto.pbkdf2Sync(password, salt, 1000, 64, 'sha512').toString('hex');

    // Encrypt sensitive data
    const encryptedUserData = encryptData({
        username,
        email,
        hashedPassword,
        salt
    }, process.env.ENCRYPTION_KEY);

    // Insert user
    const result = await usersCollection.insertOne({
        encryptedData: encryptedUserData
    });

    return result.insertedId;
}

// User login
export async function loginUser(email, password) {
    const db = await connectToDatabase();
    const usersCollection = db.collection('users');

    const userRecord = await usersCollection.findOne({ 'encryptedData': { $exists: true } });
    if (!userRecord) {
        throw new Error('Użytkownik nie został znaleziony');
    }

    // Decrypt user data
    const userData = decryptData(userRecord.encryptedData, process.env.ENCRYPTION_KEY);

    // Verify password
    const hashedInputPassword = crypto.pbkdf2Sync(password, userData.salt, 1000, 64, 'sha512').toString('hex');
    
    if (hashedInputPassword !== userData.hashedPassword) {
        throw new Error('Nieprawidłowe hasło');
    }

    // Generate JWT token
    const token = generateJWT(userData);
    return token;
}

// Google OAuth login
export async function loginWithGoogle(googleProfile) {
    const db = await connectToDatabase();
    const usersCollection = db.collection('users');

    // Check if user exists with this Google ID
    let userRecord = await usersCollection.findOne({ 
        'encryptedData.googleId': googleProfile.id 
    });

    if (!userRecord) {
        // Create new user if not exists
        const encryptedUserData = encryptData({
            username: googleProfile.name,
            email: googleProfile.email,
            googleId: googleProfile.id
        }, process.env.ENCRYPTION_KEY);

        userRecord = await usersCollection.insertOne({
            encryptedData: encryptedUserData
        });
    }

    // Generate JWT token
    const userData = decryptData(userRecord.encryptedData, process.env.ENCRYPTION_KEY);
    const token = generateJWT(userData);
    return token;
}

// JWT Token Generation
function generateJWT(userData) {
    // In a real-world scenario, use a proper JWT library like 'jsonwebtoken'
    const payload = {
        userId: userData._id,
        email: userData.email,
        username: userData.username
    };

    // Simple token generation (replace with proper JWT in production)
    return Buffer.from(JSON.stringify(payload)).toString('base64');
}

// Token Verification
export async function verifyToken(token) {
    try {
        const payload = JSON.parse(Buffer.from(token, 'base64').toString('utf-8'));
        
        const db = await connectToDatabase();
        const usersCollection = db.collection('users');

        const userRecord = await usersCollection.findOne({ 
            'encryptedData': { $exists: true } 
        });

        if (!userRecord) {
            throw new Error('Token is invalid');
        }

        return payload;
    } catch (error) {
        throw new Error('Invalid token');
    }
}