// dashboard-init.js - Script to be included in dashboard.html
import { isLoggedIn, logout, getAuthToken } from '/js/auth-client.js';
import { getCommands, toggleCommand } from '/js/commands.js';
import { getStats, renderStats } from '/js/stats.js';
import AUTH_CONFIG from '/js/auth-config.js';

// Funkcja do wyświetlania powiadomień
function showToast(message, type = 'success') {
    const toast = document.getElementById('toast');
    const toastMessage = document.getElementById('toastMessage');
    
    toastMessage.textContent = message;
    toast.className = `toast ${type} show`;
    
    setTimeout(() => {
        toast.className = 'toast';
    }, 3000);
}

// Funkcja do aktualizacji panelu sterowania
async function updateDashboard() {
    try {
        // Pobierz komendy
        const commands = await getCommands();
        renderCommandsUI(commands);
        
        // Pobierz statystyki
        const stats = await getStats();
        renderStatsUI(stats);
    } catch (error) {
        console.error('Błąd podczas aktualizacji panelu:', error);
        showToast('Błąd podczas aktualizacji panelu', 'error');
    }
}

// Funkcja do renderowania komend
function renderCommandsUI(commands) {
    const commandsContainer = document.getElementById('commands');
    
    if (!commands || commands.length === 0) {
        commandsContainer.innerHTML = '<p>Brak dostępnych komend</p>';
        return;
    }
    
    let html = '';
    commands.forEach(command => {
        html += `
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
        `;
    });
    
    commandsContainer.innerHTML = html;
    
    // Dodaj obsługę przycisków
    commandsContainer.querySelectorAll('.btn').forEach(btn => {
        btn.addEventListener('click', async (e) => {
            const id = e.target.dataset.id;
            const active = e.target.dataset.active === 'true';
            
            try {
                await toggleCommand(id, !active);
                showToast(`Komenda została ${!active ? 'włączona' : 'wyłączona'}`, 'success');
                updateDashboard(); // Odśwież panel
            } catch (error) {
                console.error('Błąd podczas przełączania komendy:', error);
                showToast('Błąd podczas przełączania komendy', 'error');
            }
        });
    });
}

// Funkcja do renderowania statystyk
function renderStatsUI(stats) {
    const statsContainer = document.getElementById('stats');
    
    if (!stats) {
        statsContainer.innerHTML = '<p>Brak dostępnych statystyk</p>';
        return;
    }
    
    statsContainer.innerHTML = renderStats(stats);
}

// Inicjalizacja kontrolera bazy danych
class DatabaseController {
    constructor(electronAPI) {
        this.electronAPI = electronAPI;
        this.dbPath = null;
        this.connected = false;
        
        this.init();
    }
    
    init() {
        const selectBtn = document.getElementById('selectDatabase');
        const disconnectBtn = document.getElementById('disconnectDatabase');
        
        if (selectBtn) {
            selectBtn.addEventListener('click', () => this.selectDatabase());
        }
        
        if (disconnectBtn) {
            disconnectBtn.addEventListener('click', () => this.disconnectDatabase());
        }
        
        // Sprawdź stan połączenia przy starcie
        this.checkConnection();
    }
    
    async checkConnection() {
        if (!this.electronAPI) return;
        
        try {
            const connection = await this.electronAPI.database.getStatus();
            if (connection.isConnected) {
                this.connected = true;
                this.dbPath = connection.path;
                this.updateUI(true);
            } else {
                this.updateUI(false);
            }
        } catch (error) {
            console.error('Błąd sprawdzania połączenia:', error);
            this.updateUI(false);
        }
    }
    
    async selectDatabase() {
        if (!this.electronAPI) {
            showToast('API Electrona nie jest dostępne', 'error');
            return;
        }
        
        try {
            const result = await this.electronAPI.database.openDatabase();
            if (result && result.success) {
                this.connected = true;
                this.dbPath = result.path;
                this.updateUI(true);
                showToast('Połączono z bazą danych', 'success');
            } else if (result) {
                showToast('Nie wybrano bazy danych', 'warning');
            }
        } catch (error) {
            console.error('Błąd podczas wybierania bazy danych:', error);
            showToast('Błąd podczas wybierania bazy danych', 'error');
        }
    }
    
    async disconnectDatabase() {
        if (!this.electronAPI) return;
        
        try {
            await this.electronAPI.database.disconnect();
            this.connected = false;
            this.dbPath = null;
            this.updateUI(false);
            showToast('Rozłączono z bazą danych', 'success');
        } catch (error) {
            console.error('Błąd podczas rozłączania bazy danych:', error);
            showToast('Błąd podczas rozłączania bazy danych', 'error');
        }
    }
    
    updateUI(connected) {
        const dbStatus = document.getElementById('dbStatus');
        const dbPath = document.getElementById('dbPath');
        const disconnectBtn = document.getElementById('disconnectDatabase');
        
        if (!dbStatus || !dbPath || !disconnectBtn) return;
        
        if (connected) {
            dbStatus.textContent = 'Połączono';
            dbStatus.className = 'status running';
            dbPath.value = this.dbPath;
            disconnectBtn.disabled = false;
        } else {
            dbStatus.textContent = 'Brak połączenia z bazą danych';
            dbStatus.className = 'status stopped';
            dbPath.value = '';
            disconnectBtn.disabled = true;
        }
    }
}

// Funkcja inicjalizacji przycisków akcji
function initActionButtons() {
    const startBotBtn = document.getElementById('startBot');
    const stopBotBtn = document.getElementById('stopBot');
    const backupDataBtn = document.getElementById('backupData');
    const exportLogsBtn = document.getElementById('exportLogs');
    
    if (startBotBtn) {
        startBotBtn.addEventListener('click', () => {
            if (window.electronAPI) {
                window.electronAPI.startBot()
                    .then(() => showToast('Bot został uruchomiony', 'success'))
                    .catch(err => {
                        console.error('Błąd uruchamiania bota:', err);
                        showToast('Błąd uruchamiania bota', 'error');
                    });
            } else {
                showToast('Funkcja niedostępna w przeglądarce', 'warning');
            }
        });
    }
    
    if (stopBotBtn) {
        stopBotBtn.addEventListener('click', () => {
            if (window.electronAPI) {
                window.electronAPI.stopBot()
                    .then(() => showToast('Bot został zatrzymany', 'success'))
                    .catch(err => {
                        console.error('Błąd zatrzymywania bota:', err);
                        showToast('Błąd zatrzymywania bota', 'error');
                    });
            } else {
                showToast('Funkcja niedostępna w przeglądarce', 'warning');
            }
        });
    }
    
    if (backupDataBtn) {
        backupDataBtn.addEventListener('click', () => {
            if (window.electronAPI) {
                window.electronAPI.backupData()
                    .then(result => {
                        if (result.success) {
                            showToast(`Kopia zapasowa utworzona: ${result.path}`, 'success');
                        } else {
                            showToast('Nie udało się utworzyć kopii zapasowej', 'warning');
                        }
                    })
                    .catch(err => {
                        console.error('Błąd tworzenia kopii zapasowej:', err);
                        showToast('Błąd tworzenia kopii zapasowej', 'error');
                    });
            } else {
                showToast('Funkcja niedostępna w przeglądarce', 'warning');
            }
        });
    }
    
    if (exportLogsBtn) {
        exportLogsBtn.addEventListener('click', () => {
            if (window.electronAPI) {
                window.electronAPI.exportLogs()
                    .then(result => {
                        if (result.success) {
                            showToast(`Logi zostały wyeksportowane: ${result.path}`, 'success');
                        } else {
                            showToast('Nie udało się wyeksportować logów', 'warning');
                        }
                    })
                    .catch(err => {
                        console.error('Błąd eksportowania logów:', err);
                        showToast('Błąd eksportowania logów', 'error');
                    });
            } else {
                showToast('Funkcja niedostępna w przeglądarce', 'warning');
            }
        });
    }
}

// Initialize everything when the DOM content is loaded
document.addEventListener('DOMContentLoaded', async () => {
    // Jeśli nie jest zalogowany, przekieruj do strony logowania
    if (!isLoggedIn()) {
        window.location.href = '/login.html';
        return;
    }

    // Sprawdź token i pobierz dane użytkownika
    try {
        const response = await fetch('/api/dashboard', {
            headers: {
                'Authorization': `Bearer ${getAuthToken()}`
            }
        });

        if (!response.ok) {
            throw new Error('Nieprawidłowy token');
        }

        const data = await response.json();
        document.getElementById('username').textContent = data.user.username || 'Użytkownik';
        
        // Załaduj komendy i statystyki
        updateDashboard();
        
        // Inicjalizuj kontroler bazy danych
        if (window.electronAPI) {
            window.databaseController = new DatabaseController(window.electronAPI);
        } else {
            console.warn('API Electrona nie jest dostępne');
            const dbStatus = document.getElementById('dbStatus');
            if (dbStatus) {
                dbStatus.textContent = 'API Electrona nie jest dostępne';
            }
        }
        
        // Inicjalizuj przyciski akcji
        initActionButtons();
        
        // Dodaj obsługę przycisku wylogowania
        const logoutBtn = document.getElementById('logoutBtn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', () => {
                logout();
            });
        }
        
        // Dodaj obsługę przycisków odświeżania
        const refreshCommandsBtn = document.getElementById('refreshCommandsBtn');
        if (refreshCommandsBtn) {
            refreshCommandsBtn.addEventListener('click', async () => {
                try {
                    const commands = await getCommands();
                    renderCommandsUI(commands);
                    showToast('Komendy zostały odświeżone', 'success');
                } catch (error) {
                    console.error('Błąd podczas odświeżania komend:', error);
                    showToast('Błąd podczas odświeżania komend', 'error');
                }
            });
        }
        
        const refreshStatsBtn = document.getElementById('refreshStatsBtn');
        if (refreshStatsBtn) {
            refreshStatsBtn.addEventListener('click', async () => {
                try {
                    const stats = await getStats();
                    renderStatsUI(stats);
                    showToast('Statystyki zostały odświeżone', 'success');
                } catch (error) {
                    console.error('Błąd podczas odświeżania statystyk:', error);
                    showToast('Błąd podczas odświeżania statystyk', 'error');
                }
            });
        }
        
    } catch (error) {
        console.error('Błąd autoryzacji:', error);
        logout(); // Wyloguj użytkownika w przypadku błędu autoryzacji
    }
});

// Eksportuj niezbędne funkcje
export {
    updateDashboard,
    showToast,
    DatabaseController
};