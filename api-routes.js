// api-routes.js
import express from 'express';
import { registerUserBackend, loginUserBackend, loginWithGoogleBackend, verifyToken } from './js/auth-client.js';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import dotenv from 'dotenv';

dotenv.config();

const router = express.Router();

// Configure Google Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `http://localhost:${process.env.PORT || 3000}/auth/google/callback`
  },
  async function(accessToken, refreshToken, profile, done) {
    try {
      // Process Google profile
      const googleProfile = {
        sub: profile.id,
        name: profile.displayName,
        email: profile.emails[0].value,
        picture: profile.photos[0].value
      };

      // Use our backend function
      const token = await loginWithGoogleBackend(googleProfile);
      return done(null, { token });
    } catch (error) {
      return done(error);
    }
  }
));

// Initialize passport
router.use(passport.initialize());

// User registration endpoint
router.post('/api/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;
    
    if (!username || !email || !password) {
      return res.status(400).json({ message: 'Wszystkie pola są wymagane' });
    }
    
    const userId = await registerUserBackend(username, email, password);
    res.status(201).json({ userId });
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

// User login endpoint
router.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ message: 'Email i hasło są wymagane' });
    }
    
    const token = await loginUserBackend(email, password);
    res.status(200).json({ token });
  } catch (error) {
    res.status(401).json({ message: error.message });
  }
});

// Google login routes
router.get('/login/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

router.get('/auth/google/callback', 
  passport.authenticate('google', { session: false, failureRedirect: '/login.html' }),
  (req, res) => {
    // Get token from passport
    const token = req.user.token;
    
    // Set token in cookie or send it in the response
    res.cookie('authToken', token, { httpOnly: true });
    
    // Redirect to the app
    res.redirect('/dashboard.html');
  }
);

// Verify authentication middleware
export const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
      return res.status(401).json({ message: 'Wymagane uwierzytelnienie' });
    }
    
    const userData = await verifyToken(token);
    req.user = userData;
    next();
  } catch (error) {
    return res.status(403).json({ message: 'Nieprawidłowy token' });
  }
};

// Protected route example
router.get('/api/user/profile', authenticateToken, (req, res) => {
  res.json({ user: req.user });
});

// API dla komend i statystyk (przykładowe implementacje)
router.get('/api/commands', authenticateToken, (req, res) => {
  // Tutaj dodaj rzeczywistą implementację pobierania komend
  const commands = [
      { id: 'cmd1', name: 'Pomoc', description: 'Wyświetla dostępne komendy', active: true },
      { id: 'cmd2', name: 'Info', description: 'Informacje o bocie', active: true }
  ];
  res.json({ commands });
});

router.post('/api/commands/:id/toggle', authenticateToken, (req, res) => {
  const { id } = req.params;
  const { active } = req.body || { active: false };
  // Tutaj dodaj rzeczywistą implementację przełączania komend
  res.json({ success: true, id, active });
});

router.get('/api/stats', authenticateToken, (req, res) => {
  // Tutaj dodaj rzeczywistą implementację pobierania statystyk
  const stats = {
      users: 120,
      servers: 5,
      commands_used: 1450
  };
  res.json(stats);
});

export default router;