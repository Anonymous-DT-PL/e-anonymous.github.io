import express from 'express';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

// ES Module equivalents for __dirname and __filename
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = 'twoj_sekretny_klucz_jwt';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Symulowana baza użytkowników (zastąp prawdziwą bazą danych)
const users = [];

// Middleware weryfikacji tokena
const authenticateToken = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    
    if (!token) return res.status(401).json({ error: 'Brak autoryzacji' });
    
    try {
        const user = jwt.verify(token, SECRET_KEY);
        req.user = user;
        next();
    } catch (error) {
        res.status(403).json({ error: 'Nieprawidłowy token' });
    }
};

// Rejestracja
app.post('/api/register', async (req, res) => {
    const { username, email, password } = req.body;
    
    // Walidacja danych
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'Wszystkie pola są wymagane' });
    }
    
    // Sprawdź, czy użytkownik już istnieje
    const existingUser = users.find(u => u.email === email);
    if (existingUser) {
        return res.status(400).json({ error: 'Użytkownik o tym emailu już istnieje' });
    }
    
    // Hashowanie hasła
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Stwórz użytkownika
    const newUser = {
        id: users.length + 1,
        username,
        email,
        password: hashedPassword,
        commands: [],
        stats: {
            commands_used: 0,
            servers: 0
        }
    };
    
    users.push(newUser);
    
    res.status(201).json({ message: 'Rejestracja udana' });
});

// Logowanie
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body;
    
    // Znajdź użytkownika
    const user = users.find(u => u.email === email);
    
    if (!user) {
        return res.status(400).json({ error: 'Nieprawidłowe dane logowania' });
    }
    
    // Sprawdź hasło
    const isPasswordValid = await bcrypt.compare(password, user.password);
    
    if (!isPasswordValid) {
        return res.status(400).json({ error: 'Nieprawidłowe dane logowania' });
    }
    
    // Wygeneruj token JWT
    const token = jwt.sign(
        { id: user.id, email: user.email, username: user.username }, 
        SECRET_KEY, 
        { expiresIn: '1h' }
    );
    
    res.json({ token, user: { username: user.username, email: user.email } });
});

// Profil użytkownika
app.get('/api/user/profile', authenticateToken, (req, res) => {
    const user = users.find(u => u.id === req.user.id);
    if (!user) {
        return res.status(404).json({ error: 'Użytkownik nie został znaleziony' });
    }
    
    res.json({
        username: user.username,
        email: user.email
    });
});

// Lista komend
app.get('/api/commands', authenticateToken, (req, res) => {
    const user = users.find(u => u.id === req.user.id);
    if (!user) {
        return res.status(404).json({ error: 'Użytkownik nie został znaleziony' });
    }

    // Domyślne komendy, które można rozszerzyć
    const defaultCommands = [
        { name: 'Wiadomości', description: 'Wyświetl prywatne wiadomości', active: true },
        { name: 'Ustawienia', description: 'Zarządzaj ustawieniami konta', active: true },
        { name: 'Historia', description: 'Przeglądaj historię aktywności', active: false }
    ];

    res.json(defaultCommands);
});

// Statystyki
app.get('/api/stats', authenticateToken, (req, res) => {
    const user = users.find(u => u.id === req.user.id);
    if (!user) {
        return res.status(404).json({ error: 'Użytkownik nie został znaleziony' });
    }

    // Przykładowe statystyki globalne
    res.json({
        users: users.length,
        servers: Math.floor(Math.random() * 50), // Losowa liczba serwerów
        commands_used: users.reduce((sum, u) => sum + (u.stats?.commands_used || 0), 0)
    });
});

// Dynamiczna obsługa tras HTML
app.get('*', (req, res) => {
    // Lista możliwych ścieżek plików
    const possibleFiles = [
        path.join(__dirname, 'public', 'html', req.path.replace(/^\//, '')),
        path.join(__dirname, 'public', req.path.replace(/^\//, '')),
        path.join(__dirname, 'public', 'html', 'index.html'),
        path.join(__dirname, 'public', 'index.html')
    ];

    // Próba znalezienia istniejącego pliku
    for (const filePath of possibleFiles) {
        if (fs.existsSync(filePath) && path.extname(filePath)) {
            return res.sendFile(filePath);
        }
    }

    // Jeśli nie znaleziono pliku, wyślij domyślny index.html
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Uruchomienie serwera
app.listen(PORT, () => {
    console.log(`Serwer działa na porcie ${PORT}`);
    console.log(`Katalog główny: ${__dirname}`);
});