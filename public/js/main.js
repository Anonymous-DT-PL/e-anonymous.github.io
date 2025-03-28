export function login() {
    window.location.href = '/login';
}

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

export async function updateDashboard() {
    try {
        const commandsHtml = await getCommands();
        const statsHtml = await getStats();
        
        document.getElementById('commands').innerHTML = commandsHtml;
        document.getElementById('stats').innerHTML = statsHtml;
    } catch (error) {
        console.error('Błąd aktualizacji dashboarda:', error);
    }
}