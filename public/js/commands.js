// commands.js
import { getAuthToken } from '/js/auth-client.js';
import AUTH_CONFIG from '/js/auth-config.js';

/**
 * Pobiera listę dostępnych komend z API
 * @returns {Promise<Array>} Lista komend
 */
export async function getCommands() {
    try {
        const response = await fetch(AUTH_CONFIG.endpoints.commands, {
            headers: {
                'Authorization': `Bearer ${getAuthToken()}`
            }
        });
        
        if (!response.ok) {
            throw new Error(`Błąd pobierania komend: ${response.status}`);
        }
        
        const data = await response.json();
        return data.commands;
    } catch (error) {
        console.error('Błąd pobierania komend:', error);
        throw error;
    }
}

/**
 * Przełącza stan komendy (aktywna/nieaktywna)
 * @param {string} commandId ID komendy do przełączenia
 * @param {boolean} active Nowy stan komendy (true - aktywna, false - nieaktywna)
 * @returns {Promise<Object>} Rezultat operacji
 */
export async function toggleCommand(commandId, active) {
    try {
        const response = await fetch(`${AUTH_CONFIG.endpoints.commands}/${commandId}/toggle`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${getAuthToken()}`,
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ active })
        });
        
        if (!response.ok) {
            throw new Error(`Błąd zmiany statusu komendy: ${response.status}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error('Błąd przełączania komendy:', error);
        throw error;
    }
}

/**
 * Funkcja pomocnicza do renderowania komend jako HTML
 * @param {Array} commands Lista komend do wyrenderowania
 * @returns {string} Kod HTML z komendami
 */
export function renderCommands(commands) {
    if (!commands || commands.length === 0) {
        return '<p>Brak dostępnych komend</p>';
    }
    
    return commands.map(command => `
        <div class="command-item">
            <div class="command-info">
                <h3>${command.name}</h3>
                <p>${command.description}</p>
            </div>
            <button class="btn ${command.active ? 'btn-secondary' : 'btn-danger'}" 
                data-id="${command.id}" data-active="${command.active}">
                ${command.active ? 'Wyłącz' : 'Włącz'}
            </button>
        </div>
    `).join('');
}

export default {
    getCommands,
    toggleCommand,
    renderCommands
};