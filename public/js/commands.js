// public/js/command.js


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