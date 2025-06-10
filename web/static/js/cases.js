// État de l'application
let currentCaseId = null;
let casesData = [];

// Éléments DOM
const casesList = document.getElementById('casesList');
const caseDetailsModal = new bootstrap.Modal(document.getElementById('caseDetailsModal'));
const caseOverview = document.getElementById('caseOverview');
const caseAgents = document.getElementById('caseAgents');
const caseQueries = document.getElementById('caseQueries');
const caseAlerts = document.getElementById('caseAlerts');
const caseNotes = document.getElementById('caseNotes');

// Fonctions utilitaires
function formatDate(isoString) {
    const date = new Date(isoString);
    return date.toLocaleString('fr-FR', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
}

function createStatusBadge(status) {
    const colors = {
        'open': 'success',
        'in_progress': 'primary',
        'closed': 'secondary'
    };
    
    const labels = {
        'open': 'Ouvert',
        'in_progress': 'En cours',
        'closed': 'Fermé'
    };
    
    const color = colors[status] || 'secondary';
    const label = labels[status] || status;
    
    return `<span class="badge bg-${color}">${label}</span>`;
}

function createPriorityBadge(priority) {
    const colors = {
        'low': 'secondary',
        'medium': 'info',
        'high': 'warning',
        'critical': 'danger'
    };
    
    const labels = {
        'low': 'Basse',
        'medium': 'Moyenne',
        'high': 'Haute',
        'critical': 'Critique'
    };
    
    const color = colors[priority] || 'secondary';
    const label = labels[priority] || priority;
    
    return `<span class="badge bg-${color}">${label}</span>`;
}

// Chargement des cas
async function loadCases() {
    try {
        const response = await fetch('/api/cases');
        const data = await response.json();
        casesData = data.cases;
        displayCases();
    } catch (error) {
        console.error('Erreur lors du chargement des cas:', error);
        showError('Impossible de charger les cas');
    }
}

// Affichage des cas
function displayCases() {
    casesList.innerHTML = '';
    
    casesData.forEach(case_ => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${case_.id}</td>
            <td>${case_.title}</td>
            <td>${createStatusBadge(case_.status)}</td>
            <td>${createPriorityBadge(case_.priority)}</td>
            <td>${case_.agent_count}</td>
            <td>${case_.query_count}</td>
            <td>${case_.alert_count}</td>
            <td>${formatDate(case_.updated_at)}</td>
            <td>
                <button class="btn btn-sm btn-outline-primary" onclick="showCaseDetails(${case_.id})">
                    <i class="bi bi-info-circle me-1"></i>
                    Détails
                </button>
            </td>
        `;
        casesList.appendChild(row);
    });
}

// Création d'un nouveau cas
async function createCase() {
    const title = document.getElementById('caseTitle').value;
    const description = document.getElementById('caseDescription').value;
    const priority = document.getElementById('casePriority').value;
    
    if (!title) {
        showError('Le titre est obligatoire');
        return;
    }
    
    try {
        const response = await fetch('/api/cases', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                title,
                description,
                priority
            })
        });
        
        if (!response.ok) {
            throw new Error('Erreur lors de la création du cas');
        }
        
        const data = await response.json();
        showSuccess('Cas créé avec succès');
        bootstrap.Modal.getInstance(document.getElementById('newCaseModal')).hide();
        document.getElementById('newCaseForm').reset();
        loadCases();
    } catch (error) {
        console.error('Erreur lors de la création du cas:', error);
        showError('Impossible de créer le cas');
    }
}

// Affichage des détails d'un cas
async function showCaseDetails(caseId) {
    currentCaseId = caseId;
    
    try {
        const response = await fetch(`/api/cases/${caseId}`);
        const data = await response.json();
        
        // Vue d'ensemble
        caseOverview.innerHTML = `
            <dl class="row">
                <dt class="col-sm-3">Titre</dt>
                <dd class="col-sm-9">${data.title}</dd>
                
                <dt class="col-sm-3">Description</dt>
                <dd class="col-sm-9">${data.description || 'Aucune'}</dd>
                
                <dt class="col-sm-3">Statut</dt>
                <dd class="col-sm-9">${createStatusBadge(data.status)}</dd>
                
                <dt class="col-sm-3">Priorité</dt>
                <dd class="col-sm-9">${createPriorityBadge(data.priority)}</dd>
                
                <dt class="col-sm-3">Créé le</dt>
                <dd class="col-sm-9">${formatDate(data.created_at)}</dd>
                
                <dt class="col-sm-3">Dernière mise à jour</dt>
                <dd class="col-sm-9">${formatDate(data.updated_at)}</dd>
            </dl>
        `;
        
        // Agents
        const agentsResponse = await fetch(`/api/cases/${caseId}/agents`);
        const agentsData = await agentsResponse.json();
        caseAgents.innerHTML = agentsData.agents.map(agent => `
            <div class="card mb-2">
                <div class="card-body">
                    <h6 class="card-title">${agent.hostname}</h6>
                    <p class="card-text">
                        <small class="text-muted">${agent.ip_address || 'N/A'}</small><br>
                        <small class="text-muted">${agent.os_info || 'OS inconnu'}</small>
                    </p>
                </div>
            </div>
        `).join('') || '<p class="text-muted">Aucun agent associé</p>';
        
        // Requêtes
        const queriesResponse = await fetch(`/api/cases/${caseId}/queries`);
        const queriesData = await queriesResponse.json();
        caseQueries.innerHTML = queriesData.queries.map(query => `
            <div class="card mb-2">
                <div class="card-body">
                    <h6 class="card-title">${query.query_text}</h6>
                    <p class="card-text">
                        <small class="text-muted">Statut: ${createStatusBadge(query.status)}</small><br>
                        <small class="text-muted">Soumis le: ${formatDate(query.submitted_at)}</small>
                    </p>
                </div>
            </div>
        `).join('') || '<p class="text-muted">Aucune requête associée</p>';
        
        // Alertes
        const alertsResponse = await fetch(`/api/cases/${caseId}/alerts`);
        const alertsData = await alertsResponse.json();
        caseAlerts.innerHTML = alertsData.alerts.map(alert => `
            <div class="card mb-2">
                <div class="card-body">
                    <h6 class="card-title">${alert.rule_title}</h6>
                    <p class="card-text">
                        <small class="text-muted">Niveau: ${createPriorityBadge(alert.rule_level)}</small><br>
                        <small class="text-muted">Détecté le: ${formatDate(alert.detected_at)}</small>
                    </p>
                </div>
            </div>
        `).join('') || '<p class="text-muted">Aucune alerte associée</p>';
        
        // Notes
        const notesResponse = await fetch(`/api/cases/${caseId}/notes`);
        const notesData = await notesResponse.json();
        caseNotes.innerHTML = notesData.notes.map(note => `
            <div class="card mb-2">
                <div class="card-body">
                    <p class="card-text">${note.content}</p>
                    <p class="card-text">
                        <small class="text-muted">
                            Par ${note.author} le ${formatDate(note.created_at)}
                        </small>
                    </p>
                </div>
            </div>
        `).join('') || '<p class="text-muted">Aucune note</p>';
        
        caseDetailsModal.show();
    } catch (error) {
        console.error('Erreur lors du chargement des détails du cas:', error);
        showError('Impossible de charger les détails du cas');
    }
}

// Ajout d'une note
async function addNote() {
    const content = document.getElementById('newNote').value;
    if (!content) return;
    
    try {
        const response = await fetch(`/api/cases/${currentCaseId}/notes`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                content,
                author: 'Analyste' // À remplacer par l'utilisateur connecté
            })
        });
        
        if (!response.ok) {
            throw new Error('Erreur lors de l\'ajout de la note');
        }
        
        document.getElementById('newNote').value = '';
        showSuccess('Note ajoutée avec succès');
        showCaseDetails(currentCaseId);
    } catch (error) {
        console.error('Erreur lors de l\'ajout de la note:', error);
        showError('Impossible d\'ajouter la note');
    }
}

// Ajout d'un agent au cas
async function addAgentToCase() {
    // À implémenter : sélection d'un agent dans une liste
    showError('Fonctionnalité à implémenter');
}

// Ajout d'une requête au cas
async function addQueryToCase() {
    // À implémenter : sélection d'une requête dans une liste
    showError('Fonctionnalité à implémenter');
}

// Ajout d'une alerte au cas
async function addAlertToCase() {
    // À implémenter : sélection d'une alerte dans une liste
    showError('Fonctionnalité à implémenter');
}

// Rafraîchissement des cas
function refreshCases() {
    loadCases();
}

// Gestion des erreurs
function showError(message) {
    const alert = document.createElement('div');
    alert.className = 'alert alert-danger alert-dismissible fade show';
    alert.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.querySelector('.container-fluid').insertBefore(alert, document.querySelector('.row'));
    
    setTimeout(() => {
        alert.remove();
    }, 5000);
}

function showSuccess(message) {
    const alert = document.createElement('div');
    alert.className = 'alert alert-success alert-dismissible fade show';
    alert.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.querySelector('.container-fluid').insertBefore(alert, document.querySelector('.row'));
    
    setTimeout(() => {
        alert.remove();
    }, 5000);
}

// Initialisation
loadCases();
setInterval(loadCases, 5000); // Rafraîchir toutes les 5 secondes 