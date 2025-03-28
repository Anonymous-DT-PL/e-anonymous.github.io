//js/stats.js
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