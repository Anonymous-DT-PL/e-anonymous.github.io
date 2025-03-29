import express from 'express';
import { Client } from 'discord.js';
import { OAuth2Client } from 'google-auth-library';
import { google } from 'googleapis';
import dotenv from 'dotenv';
import { registerUser, loginUser, loginWithGoogle, verifyToken } from './auth.js';
import path from 'path';
import { fileURLToPath } from 'url';

// Uzyskanie ścieżki bieżącego pliku dla ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Environment configuration
dotenv.config();

const app = express();

// Middleware
app.use(express.json());
app.use(express.static(__dirname)); // Serwowanie plików statycznych z głównego katalogu

// Discord bot initialization
const client = new Client({
    intents: ['Guilds', 'GuildMessages']
});
client.login(process.env.DISCORD_BOT_TOKEN);

// Inicjalizacja klienta Google OAuth
const googleOauthClient = new OAuth2Client(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    'http://localhost:8079/oauth2callback' // URL przekierowania
);

// Discord OAuth Endpoint
app.get('/login', (req, res) => {
    const url = `https://discord.com/api/oauth2/authorize?client_id=${process.env.DISCORD_CLIENT_ID}&permissions=0&scope=bot%20applications.commands`;
    res.redirect(url);
});

// Endpoint inicjalizacji logowania Google
app.get('/login/google', (req, res) => {
    const scopes = [
        'https://www.googleapis.com/auth/userinfo.email',
        'https://www.googleapis.com/auth/userinfo.profile'
    ];
    const url = googleOauthClient.generateAuthUrl({
        access_type: 'offline',
        scope: scopes
    });
    res.redirect(url);
});

// Endpoint callback po autoryzacji Google
app.get('/oauth2callback', async (req, res) => {
    try {
        const { code } = req.query;
        
        // Wymiana kodu na tokeny
        const { tokens } = await googleOauthClient.getToken(code);
        googleOauthClient.setCredentials(tokens);
        
        // Pobranie informacji o użytkowniku
        const oauth2 = google.oauth2('v2');
        const userInfo = await oauth2.userinfo.get({ auth: googleOauthClient });
        
        // Logowanie/rejestracja użytkownika
        const token = await loginWithGoogle({
            email: userInfo.data.email,
            name: userInfo.data.name,
            picture: userInfo.data.picture,
            sub: userInfo.data.id
        });
        
        // Przekierowanie z tokenem
        res.redirect(`/dashboard?token=${token}`);
    } catch (error) {
        console.error('Błąd autoryzacji Google:', error);
        res.redirect('/login?error=oauth_failed');
    }
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

// Google OAuth Endpoint (Alternative method)
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
};

// Protected Route Example
app.get('/api/dashboard', authenticateToken, (req, res) => {
    res.json({
        message: 'Welcome to your dashboard',
        user: req.user
    });
});

// Obsługa endpointu placeholder dla obrazów
app.get('/api/placeholder/:width/:height', (req, res) => {
  const width = parseInt(req.params.width, 10) || 400;
  const height = parseInt(req.params.height, 10) || 300;
  
  // Ustawienie nagłówków dla SVG
  res.setHeader('Content-Type', 'image/svg+xml');
  
  // Generowanie prostego SVG jako placeholder
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">
    <rect width="100%" height="100%" fill="#e0e0e0"/>
    <text x="50%" y="50%" font-family="Arial" font-size="24" text-anchor="middle" dominant-baseline="middle" fill="#666">${width}x${height}</text>
  </svg>`;
  
  res.send(svg);
});

// Obsługa konkretnych stron HTML
app.get('/index.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/register.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'register.html'));
});

// Dodajemy trasę główną która zawsze serwuje index.html
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Dodanie trasy catch-all dla SPA
app.get('*', (req, res) => {
  // Sprawdzamy czy żądanie dotyczy API
  if (!req.path.startsWith('/api')) {
    res.sendFile(path.join(__dirname, 'index.html'));
  } else {
    res.status(404).json({ message: 'API endpoint not found' });
  }
});

// Server Configuration
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
});