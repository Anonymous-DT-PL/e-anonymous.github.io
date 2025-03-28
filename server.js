import express from 'express';
import { Client } from 'discord.js';
import dotenv from 'dotenv';
import { registerUser, loginUser, loginWithGoogle, verifyToken } from './public/auth.js'; // Import your auth functions

// Environment configuration
dotenv.config();

const app = express();

// Middleware
app.use(express.json());
app.use(express.static('public'));

// Discord bot initialization
const client = new Client({
    intents: ['Guilds', 'GuildMessages']
});
client.login(process.env.DISCORD_BOT_TOKEN);

// Discord OAuth Endpoint
app.get('/login', (req, res) => {
    const url = `https://discord.com/api/oauth2/authorize?client_id=${process.env.DISCORD_CLIENT_ID}&permissions=0&scope=bot%20applications.commands`;
    res.redirect(url);
});

// Registration Endpoint
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const userId = await registerUser(username, email, password);
        res.status(201).json({ message: 'Rejestracja zakończona sukcesem', userId });
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});

// Login Endpoint
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const token = await loginUser(email, password);
        res.json({ token });
    } catch (error) {
        res.status(401).json({ message: error.message });
    }
});

// Google OAuth Endpoint
app.post('/api/login/google', async (req, res) => {
    try {
        const { googleProfile } = req.body;
        const token = await loginWithGoogle(googleProfile);
        res.json({ token });
    } catch (error) {
        res.status(401).json({ message: error.message });
    }
});

// Token Verification Middleware
function authenticateToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ message: 'Token is required' });
    }
    
    try {
        const user = verifyToken(token);
        req.user = user;
        next();
    } catch (error) {
        res.status(403).json({ message: 'Invalid token' });
    }
}

// Protected Route Example
app.get('/api/dashboard', authenticateToken, (req, res) => {
    res.json({
        message: 'Welcome to your dashboard',
        user: req.user
    });
});

// Server Configuration
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});