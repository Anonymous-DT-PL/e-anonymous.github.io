import express from 'express';
import { Client } from 'discord.js';
import dotenv from 'dotenv';

// Konfiguracja zmiennych środowiskowych
dotenv.config();

const app = express();
app.use(express.json());
app.use(express.static('public'));

// Inicjalizacja klienta Discord
const client = new Client({
    intents: ['Guilds', 'GuildMessages']
});

// Logowanie bota
client.login(process.env.DISCORD_BOT_TOKEN);

// Endpoint OAuth dla Discord
app.get('/login', (req, res) => {
    const url = `https://discord.com/api/oauth2/authorize?client_id=${process.env.DISCORD_CLIENT_ID}&permissions=0&scope=bot%20applications.commands`;
    res.redirect(url);
});

// Uruchomienie serwera
app.listen(process.env.PORT, () => {
    console.log(`Serwer działa na porcie ${process.env.PORT}`);
});