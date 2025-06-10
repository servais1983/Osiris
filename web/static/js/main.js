// Éléments DOM
const agentsList = document.getElementById('agents-list');
const agentSelect = document.getElementById('agent-select');
const queryForm = document.getElementById('query-form');
const queryInput = document.getElementById('query-input');
const resultsDiv = document.getElementById('results');

// État de l'application
let selectedAgentId = null;
let currentWebSocket = null;
let resultsTable = null;

// Fonctions utilitaires
function formatDate(dateString) {
    return new Date(dateString).toLocaleString();
}

function createStatusBadge(status) {
    const badges = {
        'RUNNING': 'primary',
        'COMPLETED': 'success',
        'ERROR': 'danger'
    };
    const color = badges[status] || 'secondary';
    return `<span class="badge bg-${color}">${status}</span>`;
}

// Création de la table des résultats
function createResultsTable() {
    const table = document.createElement('table');
    table.className = 'table table-hover';
    table.innerHTML = `
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>Données</th>
                <th>Actions</th>
            </tr>
        </thead>
        <tbody></tbody>
    `;
    return table;
}

// Mise à jour de la liste des agents
async function updateAgentsList() {
    try {
        const response = await fetch('/api/agents');
        const data = await response.json();
        const agentsList = document.getElementById('agentsList');
        agentsList.innerHTML = '';

        data.agents.forEach(agentId => {
            const agentItem = document.createElement('a');
            agentItem.href = '#';
            agentItem.className = `list-group-item list-group-item-action ${agentId === selectedAgentId ? 'active' : ''}`;
            agentItem.innerHTML = `
                <i class="bi bi-pc-display me-2"></i>
                ${agentId}
            `;
            agentItem.onclick = (e) => {
                e.preventDefault();
                selectAgent(agentId);
            };
            agentsList.appendChild(agentItem);
        });
    } catch (error) {
        console.error('Erreur lors de la récupération des agents:', error);
        showError('Impossible de récupérer la liste des agents');
    }
}

// Sélection d'un agent
function selectAgent(agentId) {
    selectedAgentId = agentId;
    document.querySelectorAll('#agentsList a').forEach(item => {
        item.classList.remove('active');
        if (item.textContent.trim() === agentId) {
            item.classList.add('active');
        }
    });
}

// Connexion WebSocket
function connectWebSocket(queryId) {
    if (currentWebSocket) {
        currentWebSocket.close();
    }

    const ws = new WebSocket(`ws://${window.location.host}/api/ws/results/${queryId}`);
    currentWebSocket = ws;

    ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === 'result') {
            addResultToTable(data.data);
        } else if (data.type === 'summary') {
            showSuccess(data.data.message);
        }
    };

    ws.onerror = (error) => {
        console.error('Erreur WebSocket:', error);
        showError('Erreur de connexion WebSocket');
    };

    ws.onclose = () => {
        console.log('WebSocket fermé');
    };
}

// Ajout d'un résultat à la table
function addResultToTable(data) {
    const tbody = resultsTable.querySelector('tbody');
    const row = document.createElement('tr');
    row.className = 'new-row';
    
    // Formatage des données
    const formattedData = formatResultData(data);
    
    row.innerHTML = `
        <td>${formatDate(new Date())}</td>
        <td>${formattedData}</td>
        <td>
            <div class="btn-group">
                <button class="btn btn-sm btn-outline-primary" onclick="showDetails(this)">
                    <i class="bi bi-eye"></i>
                </button>
                ${data.virustotal ? `
                    <button class="btn btn-sm btn-outline-danger" onclick="showVirusTotal(this)">
                        <i class="bi bi-shield-exclamation"></i>
                    </button>
                ` : ''}
            </div>
        </td>
    `;
    
    tbody.insertBefore(row, tbody.firstChild);
}

// Formatage des données du résultat
function formatResultData(data) {
    const items = [];
    for (const [key, value] of Object.entries(data)) {
        if (key !== 'virustotal') {
            items.push(`<strong>${key}:</strong> ${value}`);
        }
    }
    return items.join('<br>');
}

// Affichage des détails
function showDetails(button) {
    const row = button.closest('tr');
    const data = row.querySelector('td:nth-child(2)').textContent;
    const modal = new bootstrap.Modal(document.getElementById('detailsModal'));
    document.getElementById('detailsContent').textContent = data;
    modal.show();
}

// Affichage des détails VirusTotal
function showVirusTotal(button) {
    const row = button.closest('tr');
    const data = JSON.parse(row.dataset.virustotal);
    const modal = new bootstrap.Modal(document.getElementById('detailsModal'));
    document.getElementById('detailsContent').textContent = JSON.stringify(data, null, 2);
    modal.show();
}

// Soumission de la requête
async function submitQuery(event) {
    event.preventDefault();
    
    if (!selectedAgentId) {
        showError('Veuillez sélectionner un agent');
        return;
    }
    
    const queryInput = document.getElementById('queryInput');
    const query = queryInput.value.trim();
    
    if (!query) {
        showError('Veuillez entrer une requête');
        return;
    }
    
    try {
        const response = await fetch('/api/query', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                agent_id: selectedAgentId,
                query: query
            })
        });
        
        const data = await response.json();
        
        if (data.error) {
            showError(data.error);
        } else {
            // Réinitialisation de la table des résultats
            const resultsContainer = document.getElementById('resultsContainer');
            resultsContainer.innerHTML = '';
            resultsTable = createResultsTable();
            resultsContainer.appendChild(resultsTable);
            
            // Connexion WebSocket pour les résultats en temps réel
            connectWebSocket(data.query_id);
            
            showSuccess('Requête envoyée avec succès');
            
            // Mise à jour de l'historique
            updateHistory();
        }
    } catch (error) {
        console.error('Erreur lors de l\'envoi de la requête:', error);
        showError('Erreur lors de l\'envoi de la requête');
    }
}

// Mise à jour de l'historique
async function updateHistory() {
    try {
        const response = await fetch('/api/history');
        const data = await response.json();
        const historyList = document.getElementById('historyList');
        historyList.innerHTML = '';

        data.queries.forEach(query => {
            const historyItem = document.createElement('a');
            historyItem.href = '#';
            historyItem.className = 'list-group-item list-group-item-action';
            historyItem.innerHTML = `
                <div class="d-flex justify-content-between align-items-center">
                    <small class="text-muted">${formatDate(query.submitted_at)}</small>
                    ${createStatusBadge(query.status)}
                </div>
                <div class="mt-2">
                    <strong>Agent:</strong> ${query.agent_id}
                </div>
                <div class="mt-1 text-truncate">
                    <code>${query.query_string}</code>
                </div>
            `;
            historyItem.onclick = (e) => {
                e.preventDefault();
                loadQueryResults(query.query_id);
            };
            historyList.appendChild(historyItem);
        });
    } catch (error) {
        console.error('Erreur lors de la récupération de l\'historique:', error);
        showError('Impossible de récupérer l\'historique des requêtes');
    }
}

// Chargement des résultats d'une requête
async function loadQueryResults(queryId) {
    try {
        const response = await fetch(`/api/results/${queryId}`);
        const data = await response.json();
        
        // Réinitialisation de la table des résultats
        const resultsContainer = document.getElementById('resultsContainer');
        resultsContainer.innerHTML = '';
        resultsTable = createResultsTable();
        resultsContainer.appendChild(resultsTable);
        
        // Ajout des résultats à la table
        data.results.forEach(result => {
            addResultToTable(result);
        });
        
        showSuccess('Résultats chargés avec succès');
    } catch (error) {
        console.error('Erreur lors du chargement des résultats:', error);
        showError('Impossible de charger les résultats');
    }
}

// Affichage des messages
function showError(message) {
    const alert = document.createElement('div');
    alert.className = 'alert alert-danger alert-dismissible fade show';
    alert.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    document.querySelector('.container-fluid').insertBefore(alert, document.querySelector('.row'));
}

function showSuccess(message) {
    const alert = document.createElement('div');
    alert.className = 'alert alert-success alert-dismissible fade show';
    alert.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    document.querySelector('.container-fluid').insertBefore(alert, document.querySelector('.row'));
}

// Initialisation
document.addEventListener('DOMContentLoaded', () => {
    // Initialisation de la table des résultats
    resultsTable = createResultsTable();
    document.getElementById('resultsContainer').appendChild(resultsTable);
    
    // Mise à jour de la liste des agents
    updateAgentsList();
    
    // Mise à jour de l'historique
    updateHistory();
    
    // Gestion du formulaire de requête
    document.getElementById('queryForm').addEventListener('submit', submitQuery);
    
    // Mise à jour périodique
    setInterval(() => {
        updateAgentsList();
        updateHistory();
    }, 5000);
}); 