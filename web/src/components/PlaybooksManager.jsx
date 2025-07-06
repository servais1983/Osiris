import React, { useState, useEffect } from 'react';
import { FaPlay, FaPause, FaEye, FaEdit, FaTrash, FaChartLine } from 'react-icons/fa';

function PlaybooksManager() {
  const [playbooks, setPlaybooks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedPlaybook, setSelectedPlaybook] = useState(null);
  const [showSimulationModal, setShowSimulationModal] = useState(false);
  const [simulationData, setSimulationData] = useState({});

  useEffect(() => {
    loadPlaybooks();
  }, []);

  const loadPlaybooks = async () => {
    try {
      // fetch('/api/v1/automation/playbooks')
      //   .then(res => res.json())
      //   .then(data => setPlaybooks(data));
      
      // Données mockées
      const mockData = [
        {
          id: 1,
          name: "Automatic Response to Reverse Shell",
          description: "Isolates the host and kills the suspicious process upon detection of a common reverse shell.",
          trigger: "Suspicious Network Connection by Shell Process",
          is_active: true,
          stats: {
            runs: 52,
            success_rate: 98.1,
            avg_runtime_ms: 1520,
            last_execution: "2024-01-15T10:30:00Z"
          },
          sequence: [
            { name: "Kill Malicious Process", action: "kill_process" },
            { name: "Isolate Host", action: "isolate" },
            { name: "Create High-Priority Case", action: "create_case" }
          ]
        },
        {
          id: 2,
          name: "Phishing Link Clicked",
          description: "Automated response when a user clicks on a suspicious phishing link.",
          trigger: "User downloaded suspicious file from phishing email",
          is_active: false,
          stats: {
            runs: 10,
            success_rate: 70.0,
            avg_runtime_ms: 5300,
            last_execution: "2024-01-14T15:20:00Z"
          },
          sequence: [
            { name: "Block Network Access", action: "isolate" },
            { name: "Collect Evidence", action: "collect_evidence" },
            { name: "Send Alert", action: "send_notification" }
          ]
        },
        {
          id: 3,
          name: "Privilege Escalation Detected",
          description: "Response to detected privilege escalation attempts.",
          trigger: "Suspicious privilege escalation activity",
          is_active: true,
          stats: {
            runs: 25,
            success_rate: 92.0,
            avg_runtime_ms: 2100,
            last_execution: "2024-01-15T09:15:00Z"
          },
          sequence: [
            { name: "Kill Suspicious Process", action: "kill_process" },
            { name: "Create Incident Case", action: "create_case" },
            { name: "Notify Security Team", action: "send_notification" }
          ]
        }
      ];
      
      setPlaybooks(mockData);
      setLoading(false);
    } catch (error) {
      console.error('Error loading playbooks:', error);
      setLoading(false);
    }
  };

  const togglePlaybookStatus = async (playbookId, currentStatus) => {
    try {
      // fetch(`/api/v1/automation/playbooks/${playbookId}/toggle`, {
      //   method: 'POST',
      //   headers: { 'Content-Type': 'application/json' },
      //   body: JSON.stringify({ enabled: !currentStatus })
      // }).then(() => loadPlaybooks());
      
      console.log(`Toggling playbook ${playbookId} to ${!currentStatus}`);
      loadPlaybooks();
    } catch (error) {
      console.error('Error toggling playbook:', error);
    }
  };

  const handleSimulate = (playbook) => {
    setSelectedPlaybook(playbook);
    setShowSimulationModal(true);
  };

  const runSimulation = async () => {
    try {
      // fetch(`/api/v1/automation/playbooks/${selectedPlaybook.id}/simulate`, {
      //   method: 'POST',
      //   headers: { 'Content-Type': 'application/json' },
      //   body: JSON.stringify(simulationData)
      // }).then(res => res.json())
      //   .then(data => {
      //     console.log('Simulation results:', data);
      //     setShowSimulationModal(false);
      //   });
      
      console.log('Running simulation for playbook:', selectedPlaybook.id, simulationData);
      setShowSimulationModal(false);
    } catch (error) {
      console.error('Error running simulation:', error);
    }
  };

  const getSuccessRateColor = (rate) => {
    if (rate >= 90) return '#27ae60';
    if (rate >= 70) return '#f39c12';
    return '#e74c3c';
  };

  const getPerformanceStatus = (stats) => {
    if (stats.success_rate >= 90 && stats.avg_runtime_ms < 2000) return 'excellent';
    if (stats.success_rate >= 80 && stats.avg_runtime_ms < 3000) return 'good';
    if (stats.success_rate >= 70) return 'fair';
    return 'poor';
  };

  if (loading) {
    return <div className="loading">Chargement des playbooks...</div>;
  }

  return (
    <div className="playbooks-manager">
      <div className="manager-header">
        <h1>Gestion des Playbooks d'Automatisation</h1>
        <p>Configurez les scénarios de réponse automatique d'Osiris.</p>
        <button className="btn btn-primary">
          <FaEdit /> Nouveau Playbook
        </button>
      </div>

      <div className="playbooks-grid">
        {playbooks.map(playbook => (
          <div key={playbook.id} className="playbook-card">
            <div className="playbook-header">
              <h3>{playbook.name}</h3>
              <div className="playbook-status">
                <span className={`status-badge ${playbook.is_active ? 'active' : 'inactive'}`}>
                  {playbook.is_active ? 'Actif' : 'Inactif'}
                </span>
                <label className="switch">
                  <input 
                    type="checkbox" 
                    checked={playbook.is_active}
                    onChange={() => togglePlaybookStatus(playbook.id, playbook.is_active)}
                  />
                  <span className="slider round"></span>
                </label>
              </div>
            </div>

            <p className="playbook-description">{playbook.description}</p>
            
            <div className="playbook-trigger">
              <strong>Déclencheur:</strong> {playbook.trigger}
            </div>

            <div className="playbook-stats">
              <div className="stat-item">
                <FaChartLine />
                <span>Exécutions: {playbook.stats.runs}</span>
              </div>
              <div className="stat-item">
                <span style={{ color: getSuccessRateColor(playbook.stats.success_rate) }}>
                  Taux de succès: {playbook.stats.success_rate}%
                </span>
              </div>
              <div className="stat-item">
                <span>Durée moyenne: {playbook.stats.avg_runtime_ms}ms</span>
              </div>
            </div>

            <div className="playbook-performance">
              <span className={`performance-badge ${getPerformanceStatus(playbook.stats)}`}>
                {getPerformanceStatus(playbook.stats).toUpperCase()}
              </span>
            </div>

            <div className="playbook-sequence">
              <strong>Séquence d'actions:</strong>
              <ul>
                {playbook.sequence.map((step, index) => (
                  <li key={index}>
                    {index + 1}. {step.name} ({step.action})
                  </li>
                ))}
              </ul>
            </div>

            <div className="playbook-actions">
              <button 
                className="btn btn-outline"
                onClick={() => handleSimulate(playbook)}
              >
                <FaPlay /> Lancer une simulation
              </button>
              <button className="btn btn-outline">
                <FaEye /> Voir les détails
              </button>
              <button className="btn btn-outline">
                <FaEdit /> Éditer
              </button>
            </div>

            <div className="playbook-footer">
              <small>
                Dernière exécution: {new Date(playbook.stats.last_execution).toLocaleString()}
              </small>
            </div>
          </div>
        ))}
      </div>

      {/* Modal de simulation */}
      {showSimulationModal && selectedPlaybook && (
        <div className="modal-overlay" onClick={() => setShowSimulationModal(false)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3>Simulation: {selectedPlaybook.name}</h3>
            
            <div className="simulation-form">
              <div className="form-group">
                <label>Données d'alerte de test:</label>
                <textarea
                  value={simulationData.alert_data || ''}
                  onChange={(e) => setSimulationData({
                    ...simulationData,
                    alert_data: e.target.value
                  })}
                  placeholder="Entrez les données d'alerte JSON pour la simulation..."
                  rows="6"
                />
              </div>
              
              <div className="form-group">
                <label>
                  <input
                    type="checkbox"
                    checked={simulationData.dry_run || false}
                    onChange={(e) => setSimulationData({
                      ...simulationData,
                      dry_run: e.target.checked
                    })}
                  />
                  Mode simulation (dry run)
                </label>
              </div>
            </div>

            <div className="modal-actions">
              <button 
                className="btn btn-primary"
                onClick={runSimulation}
              >
                Lancer la Simulation
              </button>
              <button 
                className="btn btn-secondary"
                onClick={() => setShowSimulationModal(false)}
              >
                Annuler
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default PlaybooksManager; 