// État de l'application
let selectedAgentId = null;
let timelineData = [];

// Éléments DOM
const agentsList = document.getElementById('agentsList');
const loadTimelineBtn = document.getElementById('loadTimelineBtn');
const timelineItems = document.getElementById('timelineItems');
const detailsModal = new bootstrap.Modal(document.getElementById('detailsModal'));
const eventDetails = document.getElementById('eventDetails');

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

function createEventBadge(eventType) {
    const badges = {
        'Process Start': 'primary',
        'File Modified': 'success',
        'Program Execution': 'warning',
        'Program Execution Evidence': 'info',
        'Network Connection': 'danger',
        'YARA Match': 'secondary'
    };
    
    const color = badges[eventType] || 'secondary';
    return `<span class="badge bg-${color}">${eventType}</span>`;
}

function createSigmaBadge(level) {
    const colors = {
        'critical': 'danger',
        'high': 'warning',
        'medium': 'info',
        'low': 'secondary'
    };
    
    const color = colors[level.toLowerCase()] || 'secondary';
    return `<span class="badge bg-${color}">Sigma: ${level}</span>`;
}

// Mise à jour de la liste des agents
async function updateAgentsList() {
    try {
        const response = await fetch('/api/agents');
        const data = await response.json();
        
        agentsList.innerHTML = '';
        data.agents.forEach(agent => {
            const item = document.createElement('a');
            item.href = '#';
            item.className = `list-group-item list-group-item-action ${agent.agent_id === selectedAgentId ? 'active' : ''}`;
            item.innerHTML = `
                <div class="d-flex w-100 justify-content-between">
                    <h6 class="mb-1">${agent.hostname}</h6>
                    <small>${agent.ip_address || 'N/A'}</small>
                </div>
                <small>${agent.os_info || 'OS inconnu'}</small>
            `;
            
            item.addEventListener('click', (e) => {
                e.preventDefault();
                selectAgent(agent.agent_id);
            });
            
            agentsList.appendChild(item);
        });
    } catch (error) {
        console.error('Erreur lors de la récupération des agents:', error);
        showError('Impossible de charger la liste des agents');
    }
}

// Sélection d'un agent
function selectAgent(agentId) {
    selectedAgentId = agentId;
    loadTimelineBtn.disabled = false;
    
    // Mettre à jour l'interface
    document.querySelectorAll('#agentsList .list-group-item').forEach(item => {
        item.classList.remove('active');
    });
    document.querySelector(`#agentsList .list-group-item[data-agent-id="${agentId}"]`)?.classList.add('active');
}

// Chargement de la timeline
async function loadTimeline() {
    if (!selectedAgentId) return;
    
    try {
        const response = await fetch(`/api/timeline/${selectedAgentId}`);
        const data = await response.json();
        
        timelineData = data.timeline;
        displayTimeline();
    } catch (error) {
        console.error('Erreur lors du chargement de la timeline:', error);
        showError('Impossible de charger la timeline');
    }
}

// Affichage de la timeline
function displayTimeline() {
    timelineItems.innerHTML = '';
    
    timelineData.forEach(event => {
        const item = document.createElement('div');
        item.className = 'timeline-item';
        item.setAttribute('data-event-type', event.event_type);
        
        // Ajouter une classe si des règles Sigma correspondent
        if (event.sigma_matches && event.sigma_matches.length > 0) {
            item.classList.add('has-sigma-matches');
        }
        
        item.innerHTML = `
            <div class="timeline-date">${formatDate(event.timestamp)}</div>
            <div class="timeline-content">
                <div class="timeline-header">
                    ${createEventBadge(event.event_type)}
                    <span class="timeline-source">${event.source}</span>
                    ${event.sigma_matches ? event.sigma_matches.map(rule => createSigmaBadge(rule.level)).join('') : ''}
                </div>
                <div class="timeline-body">
                    <p class="mb-0">${event.summary}</p>
                </div>
                <div class="timeline-footer">
                    <button class="btn btn-sm btn-outline-primary" onclick="showEventDetails('${event.timestamp}')">
                        <i class="bi bi-info-circle me-1"></i>
                        Détails
                    </button>
                </div>
            </div>
        `;
        
        timelineItems.appendChild(item);
    });
}

// Affichage des détails d'un événement
function showEventDetails(timestamp) {
    const event = timelineData.find(e => e.timestamp === timestamp);
    if (!event) return;
    
    let detailsHtml = `
        <dl class="row">
            <dt class="col-sm-3">Horodatage</dt>
            <dd class="col-sm-9">${formatDate(event.timestamp)}</dd>
            
            <dt class="col-sm-3">Source</dt>
            <dd class="col-sm-9">${event.source}</dd>
            
            <dt class="col-sm-3">Type</dt>
            <dd class="col-sm-9">${event.event_type}</dd>
            
            <dt class="col-sm-3">Résumé</dt>
            <dd class="col-sm-9">${event.summary}</dd>
        </dl>
        
        <h6>Détails</h6>
        <pre class="bg-light p-3 rounded"><code>${JSON.stringify(event.details, null, 2)}</code></pre>
    `;
    
    // Ajouter les détections Sigma si présentes
    if (event.sigma_matches && event.sigma_matches.length > 0) {
        detailsHtml += `
            <h6 class="mt-4">Détections Sigma</h6>
            <div class="sigma-matches">
                ${event.sigma_matches.map(rule => `
                    <div class="card mb-3">
                        <div class="card-header d-flex justify-content-between align-items-center">
                            <h6 class="mb-0">${rule.title}</h6>
                            ${createSigmaBadge(rule.level)}
                        </div>
                        <div class="card-body">
                            <p class="card-text">${rule.description}</p>
                            <dl class="row mb-0">
                                <dt class="col-sm-3">ID</dt>
                                <dd class="col-sm-9">${rule.id}</dd>
                                
                                <dt class="col-sm-3">Auteur</dt>
                                <dd class="col-sm-9">${rule.author || 'N/A'}</dd>
                                
                                <dt class="col-sm-3">Date</dt>
                                <dd class="col-sm-9">${rule.date || 'N/A'}</dd>
                                
                                <dt class="col-sm-3">Tags</dt>
                                <dd class="col-sm-9">${rule.tags.join(', ') || 'Aucun'}</dd>
                                
                                <dt class="col-sm-3">Faux positifs</dt>
                                <dd class="col-sm-9">${rule.falsepositives.join(', ') || 'Aucun'}</dd>
                                
                                <dt class="col-sm-3">Références</dt>
                                <dd class="col-sm-9">
                                    ${rule.references ? `
                                        <ul class="list-unstyled mb-0">
                                            ${rule.references.map(ref => `<li><a href="${ref}" target="_blank">${ref}</a></li>`).join('')}
                                        </ul>
                                    ` : 'Aucune'}
                                </dd>
                            </dl>
                        </div>
                    </div>
                `).join('')}
            </div>
        `;
    }
    
    eventDetails.innerHTML = detailsHtml;
    detailsModal.show();
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

// Événements
loadTimelineBtn.addEventListener('click', loadTimeline);

// Initialisation
updateAgentsList();
setInterval(updateAgentsList, 5000); // Rafraîchir la liste des agents toutes les 5 secondes 