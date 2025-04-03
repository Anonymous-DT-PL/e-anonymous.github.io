// Logowanie
async function login(event) {
    event.preventDefault();
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    
    try {
        const response = await fetch('/api/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ email, password })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            // Zapisz token w localStorage
            localStorage.setItem('authToken', data.token);
            // Przekieruj do dashboardu
            window.location.href = '/dashboard.html';
        } else {
            // Pokaż błąd
            alert(data.error);
        }
    } catch (error) {
        console.error('Błąd logowania:', error);
        alert('Wystąpił błąd podczas logowania');
    }
}

// Rejestracja
async function register(event) {
    event.preventDefault();
    const username = document.getElementById('username').value;
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    
    if (password !== confirmPassword) {
        alert('Hasła nie są takie same');
        return;
    }
    
    try {
        const response = await fetch('/api/register', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ username, email, password })
        });
        
        const data = await response.json();
        
        if (response.ok) {
            alert('Rejestracja udana. Możesz się teraz zalogować.');
            window.location.href = '/login.html';
        } else {
            alert(data.error);
        }
    } catch (error) {
        console.error('Błąd rejestracji:', error);
        alert('Wystąpił błąd podczas rejestracji');
    }
}

// Wylogowanie
function logout() {
    localStorage.removeItem('authToken');
    window.location.href = '/login.html';
}