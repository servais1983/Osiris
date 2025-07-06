import React, { useState, useEffect } from 'react';
import { FaExclamationTriangle, FaUserShield, FaChartLine, FaClock } from 'react-icons/fa';

function RiskDashboard() {
  const [highRiskUsers, setHighRiskUsers] = useState([]);
  const [riskStats, setRiskStats] = useState({});
  const [criticalAlerts, setCriticalAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedUser, setSelectedUser] = useState(null);

  useEffect(() => {
    // Charger les données de risque
    loadRiskData();
    
    // Actualiser toutes les 30 secondes
    const interval = setInterval(loadRiskData, 30000);
    
    return () => clearInterval(interval);
  }, []);

  const loadRiskData = async () => {
    try {
      // fetch('/api/v1/analytics/risk/high-risk-users')
      //   .then(res => res.json())
      //   .then(data => setHighRiskUsers(data));
      
      // fetch('/api/v1/analytics/risk/statistics')
      //   .then(res => res.json())
      //   .then(data => setRiskStats(data));
      
      // fetch('/api/v1/analytics/risk/critical-alerts')
      //   .then(res => res.json())
      //   .then(data => setCriticalAlerts(data));
      
      // Données mockées
      setHighRiskUsers([
        {
          user: 'jdoe',
          risk_score: 85,
          risk_level: 'critical',
          last_updated: '2024-01-15T10:30:00Z',
          recent_activities: [
            'Lancement de regedit.exe à 3h du matin',
            'Connexion depuis une IP inhabituelle',
            'Tentative d\'accès à des fichiers système'
          ]
        },
        {
          user: 'admin',
          risk_score: 72,
          risk_level: 'high',
          last_updated: '2024-01-15T09:15:00Z',
          recent_activities: [
            'Utilisation de PowerShell en dehors des heures de travail',
            'Accès à des répertoires sensibles'
          ]
        },
        {
          user: 'developer1',
          risk_score: 65,
          risk_level: 'high',
          last_updated: '2024-01-15T08:45:00Z',
          recent_activities: [
            'Téléchargement de fichiers suspects',
            'Exécution de commandes de reconnaissance'
          ]
        }
      ]);
      
      setRiskStats({
        total_users_monitored: 150,
        critical_risk_users: 1,
        high_risk_users: 2,
        medium_risk_users: 5,
        low_risk_users: 12,
        normal_risk_users: 130,
        average_risk_score: 15.2,
        critical_alerts_count: 3
      });
      
      setCriticalAlerts([
        {
          user: 'jdoe',
          risk_score: 85,
          timestamp: '2024-01-15T10:30:00Z',
          event_details: {
            type: 'process_launch',
            anomaly_score: 40,
            anomaly_reasons: ['Rare process for user', 'Activity outside work hours']
          }
        }
      ]);
      
      setLoading(false);
    } catch (error) {
      console.error('Error loading risk data:', error);
      setLoading(false);
    }
  };

  const getRiskLevelColor = (level) => {
    switch (level) {
      case 'critical':
        return '#e74c3c';
      case 'high':
        return '#f39c12';
      case 'medium':
        return '#f1c40f';
      case 'low':
        return '#27ae60';
      default:
        return '#95a5a6';
    }
  };

  const getRiskLevelIcon = (level) => {
    switch (level) {
      case 'critical':
        return <FaExclamationTriangle style={{ color: '#e74c3c' }} />;
      case 'high':
        return <FaUserShield style={{ color: '#f39c12' }} />;
      default:
        return <FaUserShield style={{ color: '#95a5a6' }} />;
    }
  };

  const handleUserClick = (user) => {
    setSelectedUser(user);
  };

  const handleResetRisk = (user) => {
    if (window.confirm(`Êtes-vous sûr de vouloir remettre à zéro le score de risque de ${user.user} ?`)) {
      // fetch(`/api/v1/analytics/risk/reset/${user.user}`, { method: 'POST' })
      //   .then(() => loadRiskData());
      console.log(`Resetting risk score for user ${user.user}`);
      loadRiskData();
    }
  };

  if (loading) {
    return <div className="loading">Chargement du tableau de bord de risque...</div>;
  }

  return (
    <div className="risk-dashboard">
      <div className="dashboard-header">
        <h1>Tableau de Bord des Risques (UEBA)</h1>
        <div className="header-actions">
          <button className="btn btn-outline" onClick={loadRiskData}>
            <FaClock /> Actualiser
          </button>
        </div>
      </div>

      {/* Statistiques globales */}
      <div className="risk-stats-grid">
        <div className="stat-card">
          <h3>Utilisateurs Surveillés</h3>
          <span className="stat-number">{riskStats.total_users_monitored}</span>
        </div>
        <div className="stat-card critical">
          <h3>Risque Critique</h3>
          <span className="stat-number">{riskStats.critical_risk_users}</span>
        </div>
        <div className="stat-card high">
          <h3>Risque Élevé</h3>
          <span className="stat-number">{riskStats.high_risk_users}</span>
        </div>
        <div className="stat-card medium">
          <h3>Risque Moyen</h3>
          <span className="stat-number">{riskStats.medium_risk_users}</span>
        </div>
        <div className="stat-card">
          <h3>Score Moyen</h3>
          <span className="stat-number">{riskStats.average_risk_score?.toFixed(1)}</span>
        </div>
        <div className="stat-card">
          <h3>Alertes Critiques</h3>
          <span className="stat-number">{riskStats.critical_alerts_count}</span>
        </div>
      </div>

      <div className="dashboard-content">
        {/* Utilisateurs à risque */}
        <div className="risk-users-section">
          <h2>Utilisateurs à Risque</h2>
          <div className="risk-users-grid">
            {highRiskUsers.map((user, index) => (
              <div 
                key={index} 
                className={`user-risk-card ${user.risk_level}`}
                onClick={() => handleUserClick(user)}
              >
                <div className="user-header">
                  <div className="user-info">
                    <span className="user-name">{user.user}</span>
                    <span className="risk-level" style={{ backgroundColor: getRiskLevelColor(user.risk_level) }}>
                      {user.risk_level.toUpperCase()}
                    </span>
                  </div>
                  {getRiskLevelIcon(user.risk_level)}
                </div>
                
                <div className="risk-bar-container">
                  <div 
                    className="risk-bar" 
                    style={{ 
                      width: `${Math.min(user.risk_score, 100)}%`,
                      backgroundColor: getRiskLevelColor(user.risk_level)
                    }}
                  >
                    {user.risk_score}
                  </div>
                </div>
                
                <div className="user-actions">
                  <small>Dernière activité: {new Date(user.last_updated).toLocaleString()}</small>
                  <button 
                    className="btn btn-sm btn-outline"
                    onClick={(e) => {
                      e.stopPropagation();
                      handleResetRisk(user);
                    }}
                  >
                    Remettre à zéro
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Alertes critiques récentes */}
        <div className="critical-alerts-section">
          <h2>Alertes Critiques Récentes</h2>
          <div className="alerts-list">
            {criticalAlerts.map((alert, index) => (
              <div key={index} className="critical-alert-item">
                <div className="alert-header">
                  <FaExclamationTriangle style={{ color: '#e74c3c' }} />
                  <span className="alert-user">{alert.user}</span>
                  <span className="alert-score">Score: {alert.risk_score}</span>
                </div>
                <div className="alert-details">
                  <p><strong>Événement:</strong> {alert.event_details.type}</p>
                  <p><strong>Score d'anomalie:</strong> {alert.event_details.anomaly_score}</p>
                  <p><strong>Raisons:</strong> {alert.event_details.anomaly_reasons.join(', ')}</p>
                  <small>{new Date(alert.timestamp).toLocaleString()}</small>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Modal de détails utilisateur */}
      {selectedUser && (
        <div className="modal-overlay" onClick={() => setSelectedUser(null)}>
          <div className="modal" onClick={(e) => e.stopPropagation()}>
            <h3>Détails de l'Utilisateur: {selectedUser.user}</h3>
            <div className="user-details">
              <p><strong>Score de risque:</strong> {selectedUser.risk_score}</p>
              <p><strong>Niveau:</strong> {selectedUser.risk_level.toUpperCase()}</p>
              <p><strong>Dernière activité:</strong> {new Date(selectedUser.last_updated).toLocaleString()}</p>
              
              <h4>Activités Récentes Suspectes:</h4>
              <ul>
                {selectedUser.recent_activities.map((activity, index) => (
                  <li key={index}>{activity}</li>
                ))}
              </ul>
            </div>
            <button className="btn btn-secondary" onClick={() => setSelectedUser(null)}>
              Fermer
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default RiskDashboard; 