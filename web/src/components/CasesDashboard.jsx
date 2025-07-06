import React, { useState, useEffect } from 'react';

function CasesDashboard() {
  const [cases, setCases] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // fetch('/api/v1/cases/')
    //   .then(res => res.json())
    //   .then(data => setCases(data));
    setCases([
      {
        id: 1, 
        title: "Suspicious PowerShell Activity", 
        status: "Open", 
        priority: "High",
        created_at: "2024-01-15T10:00:00Z"
      },
      {
        id: 2,
        title: "Unusual Network Connections",
        status: "In Progress",
        priority: "Medium",
        created_at: "2024-01-14T15:30:00Z"
      }
    ]);
    setLoading(false);
  }, []);

  const getStatusColor = (status) => {
    switch (status.toLowerCase()) {
      case 'open':
        return '#28a745';
      case 'in progress':
        return '#ffc107';
      case 'closed':
        return '#6c757d';
      default:
        return '#6c757d';
    }
  };

  const getPriorityColor = (priority) => {
    switch (priority.toLowerCase()) {
      case 'critical':
        return '#dc3545';
      case 'high':
        return '#fd7e14';
      case 'medium':
        return '#ffc107';
      case 'low':
        return '#28a745';
      default:
        return '#6c757d';
    }
  };

  if (loading) {
    return <div>Chargement des cas...</div>;
  }

  return (
    <div className="dashboard-container">
      <div className="dashboard-header">
        <h1>Tableau de Bord des Cas</h1>
        <button className="btn btn-primary">+ Nouveau Cas</button>
      </div>
      
      <div className="cases-stats">
        <div className="stat-card">
          <h3>Total</h3>
          <span className="stat-number">{cases.length}</span>
        </div>
        <div className="stat-card">
          <h3>Ouverts</h3>
          <span className="stat-number">{cases.filter(c => c.status === 'Open').length}</span>
        </div>
        <div className="stat-card">
          <h3>En cours</h3>
          <span className="stat-number">{cases.filter(c => c.status === 'In Progress').length}</span>
        </div>
        <div className="stat-card">
          <h3>Critiques</h3>
          <span className="stat-number">{cases.filter(c => c.priority === 'Critical').length}</span>
        </div>
      </div>

      <div className="cases-table-container">
        <table className="cases-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Titre</th>
              <th>Statut</th>
              <th>Priorité</th>
              <th>Date de Création</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {cases.map(c => (
              <tr key={c.id}>
                <td>#{c.id}</td>
                <td>{c.title}</td>
                <td>
                  <span 
                    className="status-badge" 
                    style={{ backgroundColor: getStatusColor(c.status) }}
                  >
                    {c.status}
                  </span>
                </td>
                <td>
                  <span 
                    className="priority-badge" 
                    style={{ backgroundColor: getPriorityColor(c.priority) }}
                  >
                    {c.priority}
                  </span>
                </td>
                <td>{new Date(c.created_at).toLocaleDateString()}</td>
                <td>
                  <button className="btn btn-sm btn-outline">Voir</button>
                  <button className="btn btn-sm btn-outline">Éditer</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export default CasesDashboard; 