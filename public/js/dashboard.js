// Ładowanie informacji o użytkowniku
async function loadUserInfo() {
    const token = localStorage.getItem('authToken');
    
    if (!token) {
        window.location.href = '/login.html';
        return;
    }
    
    try {
        const response = await fetch('/api/dashboard', {
            headers: {
                'Authorization': `Bearer ${token}`
            }
        });
        
        const data = await response.json();
        
        if (response.ok) {
            const userInfoEl = document.getElementById('userInfo');
            userInfoEl.innerHTML = `
                <p>Witaj, ${data.user.username}!</p>
                <p>Email: ${data.user.email}</p>
            `;
        } else {
            throw new Error(data.error);
        }
    } catch (error) {
        console.error('Błąd ładowania danych:', error);
        logout();
    }
}

// Wywołaj przy ładowaniu strony
document.addEventListener('DOMContentLoaded', loadUserInfo);