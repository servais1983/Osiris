import React, { useState, useEffect } from 'react';
import { FaSearch, FaGlobe, FaNetworkWired, FaExclamationTriangle, FaChartLine } from 'react-icons/fa';

function GlobalHunt() {
  const [huntType, setHuntType] = useState('malware');
  const [isHunting, setIsHunting] = useState(false);
  const [huntResults, setHuntResults] = useState(null);
  const [activeHunts, setActiveHunts] = useState([]);
  const [nodes, setNodes] = useState([]);
  const [selectedNodes, setSelectedNodes] = useState([]);
  const [customQuery, setCustomQuery] = useState('');

  useEffect(() => {
    loadNodes();
    loadActiveHunts();
  }, []);

  const loadNodes = async () => {
    try {
      // fetch('/api/v1/federation/nodes')
      //   .then(res => res.json())
      //   .then(data => setNodes(data));
      
      // Données mockées
      setNodes([
        { id: 'node-1', name: 'Europe-West', region: 'Europe', status: 'healthy', agents: 45 },
        { id: 'node-2', name: 'US-East', region: 'North America', status: 'healthy', agents: 32 },
        { id: 'node-3', name: 'Asia-Pacific', region: 'Asia', status: 'warning', agents: 28 },
        { id: 'node-4', name: 'US-West', region: 'North America', status: 'healthy', agents: 38 }
      ]);
    } catch (error) {
      console.error('Error loading nodes:', error);
    }
  };

  const loadActiveHunts = async () => {
    try {
      // fetch('/api/v1/hunting/active')
      //   .then(res => res.json())
      //   .then(data => setActiveHunts(data));
      
      // Données mockées
      setActiveHunts([
        {
          id: 'hunt-1',
          type: 'malware',
          status: 'running',
          nodes_contacted: 4,
          threats_found: 12,
          started_at: '2024-01-15T10:00:00Z'
        },
        {
          id: 'hunt-2',
          type: 'lateral_movement',
          status: 'completed',
          nodes_contacted: 4,
          threats_found: 3,
          started_at: '2024-01-15T09:30:00Z'
        }
      ]);
    } catch (error) {
      console.error('Error loading active hunts:', error);
    }
  };

  const startGlobalHunt = async () => {
    setIsHunting(true);
    
    try {
      const huntData = {
        hunt_type: huntType,
        target_nodes: selectedNodes.length > 0 ? selectedNodes : null,
        parameters: {
          severity: 'high',
          time_window: '24h'
        }
      };

      // fetch('/api/v1/hunting/global', {
      //   method: 'POST',
      //   headers: { 'Content-Type': 'application/json' },
      //   body: JSON.stringify(huntData)
      // }).then(res => res.json())
      //   .then(data => {
      //     setHuntResults(data);
      //     setIsHunting(false);
      //     loadActiveHunts();
      //   });

      // Simulation
      await new Promise(resolve => setTimeout(resolve, 3000));
      
      setHuntResults({
        hunt_id: 'hunt-' + Date.now(),
        hunt_type: huntType,
        success: true,
        threats_found: Math.floor(Math.random() * 20) + 5,
        threats: [
          {
            type: 'malware',
            severity: 'high',
            description: 'Suspicious PowerShell execution detected',
            node_id: 'node-1',
            agent_id: 'agent-123',
            timestamp: new Date().toISOString()
          },
          {
            type: 'lateral_movement',
            severity: 'medium',
            description: 'Unusual network connections detected',
            node_id: 'node-2',
            agent_id: 'agent-456',
            timestamp: new Date().toISOString()
          }
        ],
        query_results: {
          total_results: 150,
          nodes_contacted: selectedNodes.length || 4,
          successful_nodes: selectedNodes.length || 4,
          total_execution_time_ms: 2500
        }
      });
      
      setIsHunting(false);
      loadActiveHunts();
      
    } catch (error) {
      console.error('Error starting global hunt:', error);
      setIsHunting(false);
    }
  };

  const executeCustomQuery = async () => {
    if (!customQuery.trim()) return;
    
    setIsHunting(true);
    
    try {
      // fetch('/api/v1/hunting/custom-query', {
      //   method: 'POST',
      //   headers: { 'Content-Type': 'application/json' },
      //   body: JSON.stringify({
      //     oql_query: customQuery,
      //     target_nodes: selectedNodes.length > 0 ? selectedNodes : null
      //   })
      // }).then(res => res.json())
      //   .then(data => {
      //     setHuntResults(data);
      //     setIsHunting(false);
      //   });

      // Simulation
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      setHuntResults({
        query_id: 'query-' + Date.now(),
        success: true,
        results: [
          {
            node_id: 'node-1',
            agent_id: 'agent-123',
            result_data: 'Custom query result 1',
            timestamp: new Date().toISOString()
          },
          {
            node_id: 'node-2',
            agent_id: 'agent-456',
            result_data: 'Custom query result 2',
            timestamp: new Date().toISOString()
          }
        ],
        total_results: 2,
        nodes_contacted: selectedNodes.length || 4,
        total_execution_time_ms: 1800
      });
      
      setIsHunting(false);
      
    } catch (error) {
      console.error('Error executing custom query:', error);
      setIsHunting(false);
    }
  };

  const getHuntTypeIcon = (type) => {
    switch (type) {
      case 'malware':
        return <FaExclamationTriangle style={{ color: '#e74c3c' }} />;
      case 'lateral_movement':
        return <FaNetworkWired style={{ color: '#f39c12' }} />;
      case 'data_exfiltration':
        return <FaChartLine style={{ color: '#3498db' }} />;
      default:
        return <FaSearch style={{ color: '#95a5a6' }} />;
    }
  };

  const getHuntTypeDescription = (type) => {
    switch (type) {
      case 'malware':
        return 'Recherche de processus malveillants et d\'activités suspectes';
      case 'lateral_movement':
        return 'Détection de mouvements latéraux dans le réseau';
      case 'data_exfiltration':
        return 'Identification de tentatives d\'exfiltration de données';
      case 'persistence':
        return 'Recherche de mécanismes de persistance';
      default:
        return 'Chasse personnalisée';
    }
  };

  return (
    <div className="global-hunt">
      <div className="hunt-header">
        <h1>Chasse Globale aux Menaces</h1>
        <p>Lancez des recherches de menaces sur tous vos nodes fédérés</p>
      </div>

      <div className="hunt-content">
        {/* Sélection des nodes */}
        <div className="nodes-selection">
          <h3>Sélection des Nodes</h3>
          <div className="nodes-grid">
            {nodes.map(node => (
              <div 
                key={node.id} 
                className={`node-card ${selectedNodes.includes(node.id) ? 'selected' : ''} ${node.status}`}
                onClick={() => {
                  if (selectedNodes.includes(node.id)) {
                    setSelectedNodes(selectedNodes.filter(id => id !== node.id));
                  } else {
                    setSelectedNodes([...selectedNodes, node.id]);
                  }
                }}
              >
                <div className="node-info">
                  <h4>{node.name}</h4>
                  <p>{node.region}</p>
                  <span className="node-status">{node.status}</span>
                </div>
                <div className="node-stats">
                  <span>{node.agents} agents</span>
                </div>
              </div>
            ))}
          </div>
          <p className="selection-info">
            {selectedNodes.length > 0 
              ? `${selectedNodes.length} node(s) sélectionné(s)` 
              : 'Tous les nodes seront utilisés'
            }
          </p>
        </div>

        {/* Types de chasse prédéfinis */}
        <div className="hunt-types">
          <h3>Types de Chasse</h3>
          <div className="hunt-types-grid">
            {['malware', 'lateral_movement', 'data_exfiltration', 'persistence'].map(type => (
              <div 
                key={type}
                className={`hunt-type-card ${huntType === type ? 'selected' : ''}`}
                onClick={() => setHuntType(type)}
              >
                {getHuntTypeIcon(type)}
                <h4>{type.replace('_', ' ').toUpperCase()}</h4>
                <p>{getHuntTypeDescription(type)}</p>
              </div>
            ))}
          </div>
        </div>

        {/* Requête personnalisée */}
        <div className="custom-query">
          <h3>Requête OQL Personnalisée</h3>
          <div className="query-input">
            <textarea
              value={customQuery}
              onChange={(e) => setCustomQuery(e.target.value)}
              placeholder="Entrez votre requête OQL personnalisée..."
              rows="4"
            />
            <button 
              className="btn btn-primary"
              onClick={executeCustomQuery}
              disabled={isHunting || !customQuery.trim()}
            >
              <FaSearch /> Exécuter la Requête
            </button>
          </div>
        </div>

        {/* Lancement de la chasse */}
        <div className="hunt-launch">
          <button 
            className="btn btn-primary btn-large"
            onClick={startGlobalHunt}
            disabled={isHunting}
          >
            {isHunting ? (
              <>
                <div className="spinner"></div>
                Chasse en cours...
              </>
            ) : (
              <>
                <FaGlobe /> Lancer la Chasse Globale
              </>
            )}
          </button>
        </div>

        {/* Résultats de chasse */}
        {huntResults && (
          <div className="hunt-results">
            <h3>Résultats de la Chasse</h3>
            
            <div className="results-summary">
              <div className="summary-card">
                <h4>Menaces Trouvées</h4>
                <span className="number">{huntResults.threats_found || huntResults.total_results}</span>
              </div>
              <div className="summary-card">
                <h4>Nodes Contactés</h4>
                <span className="number">{huntResults.query_results?.nodes_contacted}</span>
              </div>
              <div className="summary-card">
                <h4>Temps d'Exécution</h4>
                <span className="number">{(huntResults.query_results?.total_execution_time_ms / 1000).toFixed(1)}s</span>
              </div>
            </div>

            {huntResults.threats && huntResults.threats.length > 0 && (
              <div className="threats-list">
                <h4>Menaces Détectées</h4>
                {huntResults.threats.map((threat, index) => (
                  <div key={index} className="threat-item">
                    <div className="threat-header">
                      <span className={`severity-badge ${threat.severity}`}>
                        {threat.severity.toUpperCase()}
                      </span>
                      <span className="threat-type">{threat.type}</span>
                    </div>
                    <p className="threat-description">{threat.description}</p>
                    <div className="threat-details">
                      <small>Node: {threat.node_id} | Agent: {threat.agent_id}</small>
                      <small>{new Date(threat.timestamp).toLocaleString()}</small>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {huntResults.results && huntResults.results.length > 0 && (
              <div className="query-results">
                <h4>Résultats de la Requête</h4>
                {huntResults.results.map((result, index) => (
                  <div key={index} className="result-item">
                    <div className="result-header">
                      <span className="node-id">{result.node_id}</span>
                      <span className="agent-id">{result.agent_id}</span>
                    </div>
                    <p className="result-data">{result.result_data}</p>
                    <small>{new Date(result.timestamp).toLocaleString()}</small>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Chasses actives */}
        <div className="active-hunts">
          <h3>Chasses Actives</h3>
          <div className="hunts-list">
            {activeHunts.map(hunt => (
              <div key={hunt.id} className="hunt-item">
                <div className="hunt-info">
                  {getHuntTypeIcon(hunt.type)}
                  <div>
                    <h4>{hunt.type.replace('_', ' ').toUpperCase()}</h4>
                    <p>ID: {hunt.id}</p>
                  </div>
                </div>
                <div className="hunt-status">
                  <span className={`status-badge ${hunt.status}`}>
                    {hunt.status}
                  </span>
                  <div className="hunt-stats">
                    <span>{hunt.nodes_contacted} nodes</span>
                    <span>{hunt.threats_found} menaces</span>
                  </div>
                </div>
                <div className="hunt-time">
                  <small>{new Date(hunt.started_at).toLocaleString()}</small>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

export default GlobalHunt; 