import express from 'express';
import path from 'path';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const app = express();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = 'twoj_sekretny_klucz_jwt';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(process.cwd(), 'public')));

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
        password: hashedPassword
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

// Chroniony route dashboardu
app.get('/api/dashboard', authenticateToken, (req, res) => {
    res.json({ 
        message: 'Witaj w panelu!', 
        user: req.user 
    });
});

// Trasy dla stron
app.get('/', (req, res) => {
    res.sendFile(path.join(process.cwd(), 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Serwer działa na porcie ${PORT}`);
});
