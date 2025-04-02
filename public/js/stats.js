// stats.js
import { getAuthToken } from '/js/auth-client.js';
import AUTH_CONFIG from '/js/auth-config.js';

/**
 * Pobiera statystyki z API
 * @returns {Promise<Object>} Obiekt ze statystykami
 */
export async function getStats() {
    try {
        const response = await fetch(AUTH_CONFIG.endpoints.stats, {
            headers: {
                'Authorization': `Bearer ${getAuthToken()}`
            }
        });
        
        if (!response.ok) {
            throw new Error(`Błąd pobierania statystyk: ${response.status}`);
        }
        
        return await response.json();
    } catch (error) {
        console.error('Błąd pobierania statystyk:', error);
        throw error;
    }
}

/**
 * Funkcja pomocnicza do renderowania statystyk jako HTML
 * @param {Object} stats Obiekt ze statystykami
 * @returns {string} Kod HTML z statystykami
 */
export function renderStats(stats) {
    if (!stats) {
        return '<p>Brak dostępnych statystyk</p>';
    }
    
    let statsText = `Liczba użytkowników: ${stats.users}\n`;
    statsText += `Liczba serwerów: ${stats.servers}\n`;
    statsText += `Użyto komend: ${stats.commands_used}\n`;
    
    return `<pre>${statsText}</pre>`;
}

export default {
    getStats,
    renderStats
};