// État de l'application
let currentFilters = {
    status: '',
    level: '',
    case_id: ''
};

// Éléments DOM
const alertsList = document.getElementById('alertsList');
const filterForm = document.getElementById('filterForm');
const statusFilter = document.getElementById('statusFilter');
const levelFilter = document.getElementById('levelFilter');
const caseFilter = document.getElementById('caseFilter');
const alertDetailsModal = new bootstrap.Modal(document.getElementById('alertDetailsModal'));

// Variables globales
let currentAnalysis = null;
const aiAnalysisModal = new bootstrap.Modal(document.getElementById('aiAnalysisModal'));

// Initialisation
document.addEventListener('DOMContentLoaded', () => {
    loadCases();
    loadAlerts();
    setupEventListeners();
});

// Configuration des écouteurs d'événements
function setupEventListeners() {
    filterForm.addEventListener('submit', (e) => {
        e.preventDefault();
        currentFilters = {
            status: statusFilter.value,
            level: levelFilter.value,
            case_id: caseFilter.value
        };
        loadAlerts();
    });
}

// Chargement des cas pour le filtre
async function loadCases() {
    try {
        const response = await fetch('/api/cases');
        const cases = await response.json();
        
        caseFilter.innerHTML = '<option value="">Tous</option>';
        cases.forEach(case_ => {
            const option = document.createElement('option');
            option.value = case_.id;
            option.textContent = case_.title;
            caseFilter.appendChild(option);
        });
    } catch (error) {
        console.error('Erreur lors du chargement des cas:', error);
        showError('Impossible de charger la liste des cas');
    }
}

// Chargement des alertes
async function loadAlerts() {
    try {
        const queryParams = new URLSearchParams(currentFilters);
        const response = await fetch(`/api/alerts?${queryParams}`);
        const alerts = await response.json();
        
        displayAlerts(alerts);
    } catch (error) {
        console.error('Erreur lors du chargement des alertes:', error);
        showError('Impossible de charger les alertes');
    }
}

// Affichage des alertes dans le tableau
function displayAlerts(alerts) {
    alertsList.innerHTML = '';
    
    alerts.forEach(alert => {
        const row = document.createElement('tr');
        row.innerHTML = `
            <td>${alert.id}</td>
            <td>${alert.rule_title}</td>
            <td>${createLevelBadge(alert.rule_level)}</td>
            <td>${createStatusBadge(alert.status)}</td>
            <td>${formatDate(alert.detected_at)}</td>
            <td>
                <div class="btn-group btn-group-sm">
                    <button class="btn btn-outline-primary" onclick="viewAlertDetails(${alert.id})">
                        <i class="bi bi-eye"></i>
                    </button>
                    <button class="btn btn-outline-success" onclick="associateWithCase(${alert.id})">
                        <i class="bi bi-folder-plus"></i>
                    </button>
                </div>
            </td>
        `;
        alertsList.appendChild(row);
    });
}

// Affichage des détails d'une alerte
async function viewAlertDetails(alertId) {
    try {
        const response = await fetch(`/api/alerts/${alertId}`);
        const alert = await response.json();
        
        // Remplissage des champs du modal
        document.getElementById('alertId').textContent = alert.id;
        document.getElementById('alertRule').textContent = alert.rule_title;
        document.getElementById('alertLevel').innerHTML = createLevelBadge(alert.rule_level);
        document.getElementById('alertStatus').innerHTML = createStatusBadge(alert.status);
        document.getElementById('alertDetectedAt').textContent = formatDate(alert.detected_at);
        document.getElementById('alertEventData').textContent = JSON.stringify(alert.event_data, null, 2);
        
        // Configuration des sélecteurs
        document.getElementById('alertStatusSelect').value = alert.status;
        document.getElementById('alertCase').value = alert.case_id || '';
        
        // Stockage de l'ID de l'alerte pour la sauvegarde
        document.getElementById('alertDetailsModal').dataset.alertId = alertId;
        
        alertDetailsModal.show();
    } catch (error) {
        console.error('Erreur lors du chargement des détails:', error);
        showError('Impossible de charger les détails de l\'alerte');
    }
}

// Sauvegarde des modifications d'une alerte
async function saveAlertChanges() {
    const alertId = document.getElementById('alertDetailsModal').dataset.alertId;
    const status = document.getElementById('alertStatusSelect').value;
    const caseId = document.getElementById('alertCase').value;
    
    try {
        const response = await fetch(`/api/alerts/${alertId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                status,
                case_id: caseId || null
            })
        });
        
        if (response.ok) {
            showSuccess('Modifications enregistrées');
            alertDetailsModal.hide();
            loadAlerts();
        } else {
            throw new Error('Erreur lors de la sauvegarde');
        }
    } catch (error) {
        console.error('Erreur lors de la sauvegarde:', error);
        showError('Impossible d\'enregistrer les modifications');
    }
}

// Association d'une alerte à un cas
async function associateWithCase(alertId) {
    try {
        const response = await fetch(`/api/alerts/${alertId}/associate`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                case_id: currentFilters.case_id
            })
        });
        
        if (response.ok) {
            showSuccess('Alerte associée au cas');
            loadAlerts();
        } else {
            throw new Error('Erreur lors de l\'association');
        }
    } catch (error) {
        console.error('Erreur lors de l\'association:', error);
        showError('Impossible d\'associer l\'alerte au cas');
    }
}

// Export des alertes
function exportAlerts() {
    const queryParams = new URLSearchParams(currentFilters);
    window.location.href = `/api/alerts/export?${queryParams}`;
}

// Rafraîchissement des alertes
function refreshAlerts() {
    loadAlerts();
}

// Création d'un badge de niveau
function createLevelBadge(level) {
    const colors = {
        critical: 'danger',
        high: 'warning',
        medium: 'info',
        low: 'secondary'
    };
    
    return `<span class="badge bg-${colors[level]}">${level}</span>`;
}

// Création d'un badge de statut
function createStatusBadge(status) {
    const colors = {
        new: 'primary',
        in_progress: 'warning',
        resolved: 'success',
        false_positive: 'secondary'
    };
    
    const labels = {
        new: 'Nouvelle',
        in_progress: 'En cours',
        resolved: 'Résolue',
        false_positive: 'Faux positif'
    };
    
    return `<span class="badge bg-${colors[status]}">${labels[status]}</span>`;
}

// Formatage de la date
function formatDate(dateString) {
    const date = new Date(dateString);
    return date.toLocaleString('fr-FR', {
        day: '2-digit',
        month: '2-digit',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

// Affichage d'un message d'erreur
function showError(message) {
    // Implémentation à adapter selon votre système de notification
    console.error(message);
}

// Affichage d'un message de succès
function showSuccess(message) {
    // Implémentation à adapter selon votre système de notification
    console.log(message);
}

// Gestion de l'analyse IA
async function analyzeWithAI(alertId) {
    try {
        // Afficher le modal et le loader
        const modal = new bootstrap.Modal(document.getElementById('aiAnalysisModal'));
        modal.show();
        
        document.getElementById('aiAnalysisLoading').style.display = 'block';
        document.getElementById('aiAnalysisContent').style.display = 'none';
        
        // Appel à l'API
        const response = await fetch(`/api/alerts/${alertId}/analyze`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            }
        });
        
        if (!response.ok) {
            throw new Error('Erreur lors de l\'analyse');
        }
        
        const analysis = await response.json();
        
        // Mise à jour de l'interface
        document.getElementById('alertExplanation').textContent = analysis.explication;
        document.getElementById('riskAssessment').textContent = analysis.risque;
        document.getElementById('technicalContext').textContent = analysis.contexte_technique;
        
        // Étapes d'investigation
        const stepsList = document.getElementById('investigationSteps');
        stepsList.innerHTML = '';
        analysis.etapes_investigation.forEach(step => {
            const li = document.createElement('li');
            li.textContent = step;
            stepsList.appendChild(li);
        });
        
        // Requêtes OQL
        const queriesDiv = document.getElementById('oqlQueries');
        queriesDiv.innerHTML = '';
        analysis.requetes_oql.forEach(query => {
            const queryGroup = document.createElement('div');
            queryGroup.className = 'input-group mb-2';
            
            const input = document.createElement('input');
            input.type = 'text';
            input.className = 'form-control';
            input.value = query;
            input.readOnly = true;
            
            const button = document.createElement('button');
            button.className = 'btn btn-outline-primary';
            button.innerHTML = '<i class="fas fa-play"></i>';
            button.onclick = () => executeOqlQuery(query);
            
            queryGroup.appendChild(input);
            queryGroup.appendChild(button);
            queriesDiv.appendChild(queryGroup);
        });
        
        // Corrélations
        const correlationsList = document.getElementById('possibleCorrelations');
        correlationsList.innerHTML = '';
        analysis.correlations.forEach(correlation => {
            const li = document.createElement('li');
            li.textContent = correlation;
            correlationsList.appendChild(li);
        });
        
        // Afficher le contenu
        document.getElementById('aiAnalysisLoading').style.display = 'none';
        document.getElementById('aiAnalysisContent').style.display = 'block';
        
    } catch (error) {
        console.error('Erreur:', error);
        showNotification('Erreur lors de l\'analyse IA', 'danger');
    }
}

// Ajout des écouteurs d'événements
document.addEventListener('DOMContentLoaded', function() {
    // Écouteurs pour les boutons d'analyse IA
    document.querySelectorAll('.analyze-ai').forEach(button => {
        button.addEventListener('click', function() {
            const alertId = this.dataset.alertId;
            analyzeWithAI(alertId);
        });
    });
});

// Exécution d'une requête OQL suggérée
function executeOqlQuery(query) {
    // Fermer le modal d'analyse
    aiAnalysisModal.hide();
    
    // Remplir le champ de requête
    document.getElementById('queryInput').value = query;
    
    // Soumettre la requête
    document.getElementById('queryForm').dispatchEvent(new Event('submit'));
} 