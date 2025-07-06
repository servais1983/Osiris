import React, { useState, useEffect } from 'react';
import { FaUserShield, FaNetworkWired, FaTrash, FaSkull } from 'react-icons/fa';

function AgentDetailView({ agentId }) {
  const [agent, setAgent] = useState(null);
  const [actions, setActions] = useState([]);
  const [loading, setLoading] = useState(true);
  const [executingAction, setExecutingAction] = useState(false);

  useEffect(() => {
    // Charger les détails de l'agent
    // fetch(`/api/v1/agents/${agentId}`)
    //   .then(res => res.json())
    //   .then(data => setAgent(data));
    
    // Charger les actions disponibles
    // fetch(`/api/v1/agents/${agentId}/actions`)
    //   .then(res => res.json())
    //   .then(data => setActions(data.available_actions));
    
    // Données mockées
    setAgent({
      id: agentId,
      name: "WS-ADMIN-01",
      platform: "Windows",
      status: "Online",
      last_seen: "2024-01-15T10:30:00Z",
      ip_address: "192.168.1.100",
      version: "1.0.0"
    });
    
    setActions({
      isolate: {
        name: "Isolate Host",
        description: "Isoler l'hôte du réseau en bloquant tout le trafic sauf vers le Hive",
        requires_confirmation: true,
        danger_level: "high"
      },
      deisolate: {
        name: "Restore Connectivity",
        description: "Restaurer la connectivité réseau",
        requires_confirmation: false,
        danger_level: "low"
      },
      kill_process: {
        name: "Kill Process",
        description: "Terminer un processus spécifique",
        requires_confirmation: true,
        danger_level: "medium"
      },
      delete_file: {
        name: "Delete File",
        description: "Supprimer un fichier du système",
        requires_confirmation: true,
        danger_level: "high"
      }
    });
    
    setLoading(false);
  }, [agentId]);

  const handleAction = async (actionName) => {
    const action = actions[actionName];
    
    if (!action) return;
    
    // Vérification de confirmation pour les actions dangereuses
    if (action.requires_confirmation) {
      const confirmed = window.confirm(
        `ÊTES-VOUS SÛR de vouloir exécuter l'action "${action.name}" ?\n\n` +
        `${action.description}\n\n` +
        "Cette action peut avoir des conséquences importantes sur le système."
      );
      
      if (!confirmed) return;
    }
    
    setExecutingAction(true);
    
    try {
      // fetch(`/api/v1/agents/${agentId}/actions/${actionName}`, { 
      //   method: 'POST',
      //   headers: { 'Content-Type': 'application/json' }
      // })
      //   .then(res => res.json())
      //   .then(data => {
      //     if (data.status === 'success') {
      //       alert(`${action.name} exécutée avec succès !`);
      //     } else {
      //       alert(`Erreur: ${data.message}`);
      //     }
      //   });
      
      console.log(`Executing action ${actionName} on agent ${agentId}`);
      
      // Simulation de délai
      await new Promise(resolve => setTimeout(resolve, 1000));
      
      alert(`${action.name} exécutée avec succès !`);
      
    } catch (error) {
      console.error('Error executing action:', error);
      alert('Erreur lors de l\'exécution de l\'action');
    } finally {
      setExecutingAction(false);
    }
  };

  const getDangerLevelColor = (level) => {
    switch (level) {
      case 'high':
        return '#e74c3c';
      case 'medium':
        return '#f39c12';
      case 'low':
        return '#27ae60';
      default:
        return '#95a5a6';
    }
  };

  const getActionIcon = (actionName) => {
    switch (actionName) {
      case 'isolate':
        return <FaUserShield />;
      case 'deisolate':
        return <FaNetworkWired />;
      case 'kill_process':
        return <FaSkull />;
      case 'delete_file':
        return <FaTrash />;
      default:
        return <FaUserShield />;
    }
  };

  if (loading) {
    return <div>Chargement des détails de l'agent...</div>;
  }

  if (!agent) {
    return <div>Agent non trouvé</div>;
  }

  return (
    <div className="agent-detail-container">
      <div className="agent-header">
        <h1>Agent: {agent.name}</h1>
        <div className="agent-status">
          <span className={`status-badge ${agent.status.toLowerCase()}`}>
            {agent.status}
          </span>
        </div>
      </div>

      <div className="agent-info-grid">
        <div className="info-card">
          <h3>Informations Système</h3>
          <div className="info-item">
            <strong>Plateforme:</strong> {agent.platform}
          </div>
          <div className="info-item">
            <strong>Version:</strong> {agent.version}
          </div>
          <div className="info-item">
            <strong>Adresse IP:</strong> {agent.ip_address}
          </div>
          <div className="info-item">
            <strong>Dernière activité:</strong> {new Date(agent.last_seen).toLocaleString()}
          </div>
        </div>

        <div className="info-card">
          <h3>Actions de Réponse</h3>
          <div className="actions-grid">
            {Object.entries(actions).map(([actionName, action]) => (
              <button
                key={actionName}
                className={`action-button ${actionName}-button`}
                style={{ 
                  backgroundColor: getDangerLevelColor(action.danger_level),
                  opacity: executingAction ? 0.6 : 1
                }}
                onClick={() => handleAction(actionName)}
                disabled={executingAction}
              >
                {getActionIcon(actionName)}
                <span>{action.name}</span>
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="action-descriptions">
        <h3>Description des Actions</h3>
        <div className="descriptions-grid">
          {Object.entries(actions).map(([actionName, action]) => (
            <div key={actionName} className="description-item">
              <h4>{action.name}</h4>
              <p>{action.description}</p>
              <div className="danger-level">
                Niveau de danger: 
                <span style={{ color: getDangerLevelColor(action.danger_level) }}>
                  {action.danger_level.toUpperCase()}
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {executingAction && (
        <div className="execution-overlay">
          <div className="execution-modal">
            <div className="spinner"></div>
            <p>Exécution de l'action en cours...</p>
          </div>
        </div>
      )}
    </div>
  );
}

export default AgentDetailView; 