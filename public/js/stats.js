// stats.js
import { getAuthToken } from './auth-client.js';
import AUTH_CONFIG from './auth-config.js';

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

// Helper function to render stats
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