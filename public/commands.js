// public/commands.js
export async function getCommands() {
    try {
        const response = await fetch('/api/commands');
        if (!response.ok) throw new Error(`Błąd pobierania komend: ${response.status}`);
        const data = await response.json();
        return data.commands.map(command => `
            <div class="command-item">
                <h3>${command.name}</h3>
                <p>Opis: ${command.description}</p>
                <button onclick="toggleCommand('${command.id}')">Zmień status</button>
            </div>
        `).join('');
    } catch (error) {
        console.error('Błąd:', error);
        return '<div class="error">Wystąpił błąd podczas ładowania komend</div>';
    }
}

// stats.js
export async function getStats() {
    try {
        const response = await fetch('/api/stats');
        if (!response.ok) throw new Error(`Błąd pobierania statystyk: ${response.status}`);
        const data = await response.json();
        return `<pre>${JSON.stringify(data, null, 2)}</pre>`;
    } catch (error) {
        console.error('Błąd:', error);
        return '<div class="error">Wystąpił błąd podczas ładowania statystyk</div>';
    }
}

// main.js
export async function toggleCommand(commandId) {
    try {
        const response = await fetch(`/api/commands/${commandId}/toggle`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${localStorage.getItem('discordToken')}`
            }
        });
        
        if (!response.ok) throw new Error(`Błąd zmiany statusu komendy: ${response.status}`);
        
        // Odśwież dashboard po udanej operacji
        await updateDashboard();
    } catch (error) {
        console.error('Błąd:', error);
        alert('Wystąpił błąd podczas zmiany statusu komendy');
    }
}

async function login() {
    window.location.href = '/login';
}

// Inicjalizacja panelu po załogowaniu
document.addEventListener('DOMContentLoaded', async () => {
    const isLoggedIn = localStorage.getItem('discordToken');
    if (isLoggedIn) {
        showDashboard();
        await updateDashboard();
    }
});

async function updateDashboard() {
    try {
        const commandsHtml = await getCommands();
        const statsHtml = await getStats();
        
        document.getElementById('commands').innerHTML = commandsHtml;
        document.getElementById('stats').innerHTML = statsHtml;
    } catch (error) {
        console.error('Błąd aktualizacji dashboarda:', error);
    }
}

function showDashboard() {
    document.getElementById('login-section').style.display = 'none';
    document.getElementById('dashboard').style.display = 'block';
}