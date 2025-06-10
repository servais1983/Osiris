// État de l'application
let currentQuery = '';
let queryResults = null;

// Traduction en OQL
async function translateToOql() {
    const queryInput = document.getElementById('naturalLanguageQuery');
    const resultDiv = document.getElementById('oqlTranslationResult');
    const errorDiv = document.getElementById('oqlTranslationError');
    const oqlEditor = document.getElementById('oqlEditor');
    
    try {
        // Vérification de la saisie
        if (!queryInput.value.trim()) {
            throw new Error('Veuillez saisir une requête en langage naturel');
        }
        
        // Appel à l'API
        const response = await fetch('/api/translate_oql', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                query: queryInput.value.trim()
            })
        });
        
        if (!response.ok) {
            throw new Error('Erreur lors de la traduction');
        }
        
        const result = await response.json();
        
        if (!result.success) {
            throw new Error(result.error || 'Erreur lors de la traduction');
        }
        
        // Mise à jour de l'interface
        document.getElementById('generatedOqlQuery').value = result.query;
        oqlEditor.value = result.query;
        currentQuery = result.query;
        
        // Affichage des métadonnées
        displayQueryMetadata(result.metadata);
        
        resultDiv.style.display = 'block';
        errorDiv.style.display = 'none';
        
        // Feedback visuel
        showNotification('Requête OQL générée avec succès', 'success');
        
    } catch (error) {
        console.error('Erreur:', error);
        errorDiv.textContent = error.message;
        errorDiv.style.display = 'block';
        resultDiv.style.display = 'none';
        showNotification(error.message, 'danger');
    }
}

// Affichage des métadonnées
function displayQueryMetadata(metadata) {
    // Tables utilisées
    const tablesUsed = document.getElementById('tablesUsed');
    tablesUsed.innerHTML = '';
    metadata.tables_used.forEach(table => {
        const badge = document.createElement('span');
        badge.className = 'badge bg-info me-1';
        badge.textContent = table;
        tablesUsed.appendChild(badge);
    });
    
    // Complexité
    const complexity = document.getElementById('queryComplexity');
    complexity.textContent = metadata.complexity;
    complexity.className = `badge bg-${getComplexityColor(metadata.complexity)}`;
    
    // Optimisations
    const optimizations = document.getElementById('queryOptimizations');
    optimizations.innerHTML = '';
    metadata.optimizations.forEach(opt => {
        const li = document.createElement('li');
        li.className = 'mb-2';
        li.innerHTML = `
            <i class="fas fa-lightbulb text-warning me-2"></i>
            ${opt}
        `;
        optimizations.appendChild(li);
    });
}

// Couleur de la complexité
function getComplexityColor(complexity) {
    switch (complexity) {
        case 'faible':
            return 'success';
        case 'moyenne':
            return 'warning';
        case 'élevée':
            return 'danger';
        default:
            return 'secondary';
    }
}

// Copie de la requête OQL
function copyOqlQuery() {
    const queryText = document.getElementById('generatedOqlQuery');
    queryText.select();
    document.execCommand('copy');
    
    // Feedback visuel
    const copyButton = document.querySelector('#oqlTranslationResult .btn-outline-primary');
    const originalText = copyButton.innerHTML;
    copyButton.innerHTML = '<i class="fas fa-check"></i>';
    setTimeout(() => {
        copyButton.innerHTML = originalText;
    }, 2000);
    
    showNotification('Requête copiée dans le presse-papiers', 'success');
}

// Exécution de la requête générée
function executeGeneratedQuery() {
    const query = document.getElementById('generatedOqlQuery').value;
    if (query) {
        executeQuery(query);
    }
}

// Exécution d'une requête OQL
async function executeQuery(query = null) {
    const queryToExecute = query || document.getElementById('oqlEditor').value;
    
    if (!queryToExecute.trim()) {
        showNotification('Veuillez saisir une requête OQL', 'warning');
        return;
    }
    
    try {
        // Mise à jour de l'interface
        document.getElementById('queryResults').innerHTML = `
            <div class="text-center py-5">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">Chargement...</span>
                </div>
                <p class="mt-3">Exécution de la requête en cours...</p>
            </div>
        `;
        
        // Appel à l'API
        const response = await fetch('/api/execute_query', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                query: queryToExecute
            })
        });
        
        if (!response.ok) {
            throw new Error('Erreur lors de l\'exécution de la requête');
        }
        
        const result = await response.json();
        
        if (!result.success) {
            throw new Error(result.error || 'Erreur lors de l\'exécution de la requête');
        }
        
        // Affichage des résultats
        displayQueryResults(result.results);
        
        // Mise à jour de l'état
        currentQuery = queryToExecute;
        queryResults = result.results;
        
        showNotification('Requête exécutée avec succès', 'success');
        
    } catch (error) {
        console.error('Erreur:', error);
        document.getElementById('queryResults').innerHTML = `
            <div class="alert alert-danger">
                <i class="fas fa-exclamation-circle me-2"></i>
                ${error.message}
            </div>
        `;
        showNotification(error.message, 'danger');
    }
}

// Affichage des résultats
function displayQueryResults(results) {
    if (!results || results.length === 0) {
        document.getElementById('queryResults').innerHTML = `
            <div class="text-center text-muted py-5">
                <i class="fas fa-search fa-3x mb-3"></i>
                <p>Aucun résultat trouvé</p>
            </div>
        `;
        return;
    }
    
    // Création du tableau
    const table = document.createElement('table');
    table.className = 'table table-striped table-hover';
    
    // En-têtes
    const thead = document.createElement('thead');
    const headerRow = document.createElement('tr');
    Object.keys(results[0]).forEach(key => {
        const th = document.createElement('th');
        th.textContent = key;
        headerRow.appendChild(th);
    });
    thead.appendChild(headerRow);
    table.appendChild(thead);
    
    // Corps du tableau
    const tbody = document.createElement('tbody');
    results.forEach(row => {
        const tr = document.createElement('tr');
        Object.values(row).forEach(value => {
            const td = document.createElement('td');
            td.textContent = value;
            tr.appendChild(td);
        });
        tbody.appendChild(tr);
    });
    table.appendChild(tbody);
    
    // Mise à jour de l'interface
    document.getElementById('queryResults').innerHTML = '';
    document.getElementById('queryResults').appendChild(table);
}

// Effacement de la requête
function clearQuery() {
    document.getElementById('oqlEditor').value = '';
    currentQuery = '';
    document.getElementById('queryResults').innerHTML = `
        <div class="text-center text-muted py-5">
            <i class="fas fa-search fa-3x mb-3"></i>
            <p>Exécutez une requête pour voir les résultats</p>
        </div>
    `;
    showNotification('Requête effacée', 'info');
}

// Sauvegarde de la requête
async function saveQuery() {
    const query = document.getElementById('oqlEditor').value;
    
    if (!query.trim()) {
        showNotification('Veuillez saisir une requête à sauvegarder', 'warning');
        return;
    }
    
    try {
        const response = await fetch('/api/save_query', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                query: query,
                name: `Requête du ${new Date().toLocaleString()}`
            })
        });
        
        if (!response.ok) {
            throw new Error('Erreur lors de la sauvegarde');
        }
        
        const result = await response.json();
        
        if (!result.success) {
            throw new Error(result.error || 'Erreur lors de la sauvegarde');
        }
        
        showNotification('Requête sauvegardée avec succès', 'success');
        
    } catch (error) {
        console.error('Erreur:', error);
        showNotification(error.message, 'danger');
    }
}

// Affichage des notifications
function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `alert alert-${type} alert-dismissible fade show position-fixed top-0 end-0 m-3`;
    notification.style.zIndex = '1050';
    notification.innerHTML = `
        ${message}
        <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
    `;
    
    document.body.appendChild(notification);
    
    setTimeout(() => {
        notification.remove();
    }, 5000);
}

// Initialisation
document.addEventListener('DOMContentLoaded', function() {
    // Configuration de l'éditeur OQL
    const oqlEditor = document.getElementById('oqlEditor');
    oqlEditor.addEventListener('keydown', function(e) {
        if (e.key === 'Enter' && e.ctrlKey) {
            executeQuery();
        }
    });
}); 