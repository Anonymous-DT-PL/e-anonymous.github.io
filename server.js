// server.js
import express from 'express';
import { fileURLToPath } from 'url';
import path from 'path';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { OAuth2Client } from 'google-auth-library';
import { google } from 'googleapis';
import dotenv from 'dotenv';
import { 
  registerUserBackend, 
  loginUserBackend, 
  loginWithGoogleBackend, 
  verifyToken 
} from './js/auth-client.js';

// Environment configuration
dotenv.config();

// Uzyskanie ścieżki bieżącego pliku dla ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Definicja portu - używaj zmiennej środowiskowej PORT lub domyślnie 3000
const PORT = process.env.PORT || 3000;

// Database setup
let dbManager = null;

// Try to import and set up database
try {
  const DatabaseManagerModule = await import('./src/main/database/db-manager.js');
  const DatabaseManager = DatabaseManagerModule.default || DatabaseManagerModule;
  
  dbManager = new DatabaseManager(process.env.DB_PATH || path.join(__dirname, 'database.db'));
  await dbManager.connect();
  await dbManager.init();
  
  // Make it available globally
  global.dbManager = dbManager;
  
  console.log('Database connected successfully');
} catch (error) {
  console.error('Error connecting to database:', error);
  console.warn('Starting without database connection - some features may not work');
}

const app = express();

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public'))); // Serwowanie plików statycznych z katalogu public

// Inicjalizacja klienta Google OAuth
const googleOauthClient = new OAuth2Client(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    `http://localhost:${PORT}/auth/google/callback` // URL przekierowania
);

// Token Verification Middleware
function authenticateToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1] || 
                 req.cookies?.authToken;
    
    if (!token) {
        return res.status(401).json({ message: 'Token wymagany' });
    }
    
    try {
        const user = verifyToken(token);
        req.user = user;
        next();
    } catch (error) {
        res.status(403).json({ message: 'Nieprawidłowy token' });
    }
}

// API endpoints
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        if (!username || !email || !password) {
          return res.status(400).json({ message: 'Wszystkie pola są wymagane' });
        }
        
        const userId = await registerUserBackend(username, email, password);
        res.status(201).json({ message: 'Rejestracja zakończona sukcesem', userId });
    } catch (error) {
        res.status(400).json({ message: error.message });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        if (!email || !password) {
          return res.status(400).json({ message: 'Email i hasło są wymagane' });
        }
        
        const token = await loginUserBackend(email, password);
        
        // Set token in cookie
        res.cookie('authToken', token, { 
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 24 * 60 * 60 * 1000 // 24 hours
        });
        
        res.json({ token });
    } catch (error) {
        res.status(401).json({ message: error.message });
    }
});

// Google OAuth Endpoints
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

app.get('/auth/google/callback', async (req, res) => {
    try {
        const { code } = req.query;
        
        // Wymiana kodu na tokeny
        const { tokens } = await googleOauthClient.getToken(code);
        googleOauthClient.setCredentials(tokens);
        
        // Pobranie informacji o użytkowniku
        const oauth2 = google.oauth2('v2');
        const userInfo = await oauth2.userinfo.get({ auth: googleOauthClient });
        
        // Logowanie/rejestracja użytkownika
        const token = await loginWithGoogleBackend({
            email: userInfo.data.email,
            name: userInfo.data.name,
            picture: userInfo.data.picture,
            sub: userInfo.data.id
        });
        
        // Set token in cookie
        res.cookie('authToken', token, { 
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 24 * 60 * 60 * 1000 // 24 hours
        });
        
        // Przekierowanie z tokenem
        res.redirect(`/dashboard.html?token=${token}`);
    } catch (error) {
        console.error('Błąd autoryzacji Google:', error);
        res.redirect('/login.html?error=oauth_failed');
    }
});

// Logout endpoint
app.get('/api/logout', (req, res) => {
    res.clearCookie('authToken');
    res.json({ message: 'Wylogowano pomyślnie' });
});

// Przykładowy endpoint chroniony
app.get('/api/dashboard', authenticateToken, (req, res) => {
    res.json({
        message: 'Witaj w panelu sterowania',
        user: req.user
    });
});

// API dla komend i statystyk (przykładowe implementacje)
app.get('/api/commands', authenticateToken, (req, res) => {
    // Tutaj dodaj rzeczywistą implementację pobierania komend
    const commands = [
        { id: 'cmd1', name: 'Pomoc', description: 'Wyświetla dostępne komendy', active: true },
        { id: 'cmd2', name: 'Info', description: 'Informacje o bocie', active: true }
    ];
    res.json({ commands });
});

app.post('/api/commands/:id/toggle', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { active } = req.body;
    // Tutaj dodaj rzeczywistą implementację przełączania komend
    res.json({ success: true, id, active });
});

app.get('/api/stats', authenticateToken, (req, res) => {
    // Tutaj dodaj rzeczywistą implementację pobierania statystyk
    const stats = {
        users: 120,
        servers: 5,
        commands_used: 1450
    };
    res.json(stats);
});

// Database status endpoint
app.get('/api/database/status', authenticateToken, async (req, res) => {
  try {
    // Only admins can view database status (for security)
    if (req.user.role !== 'admin') {
      return res.status(403).json({ 
        message: 'Nie masz uprawnień do wyświetlania statusu bazy danych'
      });
    }

    if (!dbManager || !dbManager.isConnected()) {
      return res.status(200).json({
        connected: false,
        message: 'Baza danych nie jest połączona'
      });
    }

    // Get database version
    const versionQuery = await new Promise((resolve, reject) => {
      dbManager.db.get('SELECT sqlite_version() as version', [], (err, row) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(row);
      });
    });

    // Get tables
    const tablesQuery = await new Promise((resolve, reject) => {
      dbManager.db.all(
        'SELECT name FROM sqlite_master WHERE type="table" AND name NOT LIKE "sqlite_%"', 
        [], 
        (err, rows) => {
          if (err) {
            reject(err);
            return;
          }
          resolve(rows);
        }
      );
    });

    // Get user count
    const userCountQuery = await new Promise((resolve, reject) => {
      dbManager.db.get('SELECT COUNT(*) as count FROM users', [], (err, row) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(row);
      });
    });

    res.status(200).json({
      connected: true,
      message: 'Baza danych połączona',
      version: versionQuery.version,
      tables: tablesQuery.map(t => t.name),
      userCount: userCountQuery.count,
      path: dbManager.getDatabasePath()
    });
  } catch (error) {
    console.error('Błąd pobierania statusu bazy danych:', error);
    res.status(500).json({ 
      message: 'Błąd pobierania statusu bazy danych',
      error: error.message
    });
  }
});

// Database query endpoint - restricted to admins only
app.post('/api/database/query', authenticateToken, async (req, res) => {
  try {
    // Only admins can run queries (for security)
    if (req.user.role !== 'admin') {
      return res.status(403).json({ 
        message: 'Nie masz uprawnień do wykonywania zapytań do bazy danych'
      });
    }

    if (!dbManager || !dbManager.isConnected()) {
      return res.status(400).json({
        message: 'Baza danych nie jest połączona'
      });
    }

    const { query, params } = req.body;
    
    if (!query) {
      return res.status(400).json({ message: 'Zapytanie jest wymagane' });
    }
    
    // Security check - only allow SELECT queries
    const trimmedSql = query.trim().toLowerCase();
    if (!trimmedSql.startsWith('select')) {
      return res.status(400).json({ 
        message: 'Ze względów bezpieczeństwa dozwolone są tylko zapytania SELECT' 
      });
    }
    
    // Execute query
    const results = await new Promise((resolve, reject) => {
      dbManager.db.all(query, params || [], (err, rows) => {
        if (err) {
          reject(err);
          return;
        }
        resolve(rows);
      });
    });
    
    res.status(200).json({ results });
  } catch (error) {
    console.error('Błąd wykonywania zapytania do bazy danych:', error);
    res.status(500).json({ 
      message: 'Błąd wykonywania zapytania do bazy danych',
      error: error.message
    });
  }
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

// Dodanie przekierowań dla podstawowych stron HTML
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'register.html'));
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

// Server start
app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on port ${PORT}`);
});

// Handle graceful shutdown
process.on('SIGINT', async () => {
    console.log('Shutting down server...');
    if (dbManager) {
        await dbManager.close();
        console.log('Database connection closed');
    }
    process.exit(0);
});

export { app, authenticateToken, dbManager };