import React, { useState, useEffect } from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { Shield, Server, FileText, ChevronsRight, Home, Users, AlertTriangle, Send, RefreshCw } from 'lucide-react';

// --- Données et Fonctions de l'API ---

// Simule un appel API pour obtenir les agents
const fetchAgents = async () => {
    try {
        const response = await fetch('/api/agents');
        if (!response.ok) {
            throw new Error('Erreur réseau ou serveur');
        }
        return await response.json();
    } catch (error) {
        console.error("Impossible de récupérer les agents:", error);
        return []; // Retourne un tableau vide en cas d'erreur
    }
};

// Simule un appel API pour soumettre une requête
const submitQuery = async (agentId, queryString) => {
    try {
        const response = await fetch('/api/submit_query', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ agent_id: agentId, query_string: queryString }),
        });
        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || 'Erreur lors de la soumission');
        }
        return await response.json();
    } catch (error) {
        console.error("Erreur de soumission:", error);
        throw error;
    }
};

// --- Composants de l'UI ---

const StatCard = ({ title, value, icon, color }) => (
  <div className="bg-slate-800 p-6 rounded-lg shadow-lg flex items-center">
    <div className={`p-3 rounded-full mr-4 ${color}`}>{icon}</div>
    <div>
      <h3 className="text-slate-400 text-sm font-medium">{title}</h3>
      <p className="text-white text-3xl font-bold">{value}</p>
    </div>
  </div>
);

const Dashboard = ({ agentCount }) => (
    <>
        <h2 className="text-3xl font-bold text-white mb-6">Tableau de Bord</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
            <StatCard title="Agents Connectés" value={agentCount} icon={<Server size={24} className="text-white"/>} color="bg-green-500" />
            <StatCard title="Alertes (24h)" value="0" icon={<AlertTriangle size={24} className="text-white"/>} color="bg-yellow-500" />
            <StatCard title="Cas Actifs" value="0" icon={<FileText size={24} className="text-white"/>} color="bg-blue-500" />
            <StatCard title="Utilisateurs" value="1" icon={<Users size={24} className="text-white"/>} color="bg-indigo-500" />
        </div>
    </>
);

const AgentsView = ({ agents, onRefresh }) => (
    <>
        <div className="flex justify-between items-center mb-6">
            <h2 className="text-3xl font-bold text-white">Gestion des Agents</h2>
            <button onClick={onRefresh} className="p-2 rounded-full hover:bg-slate-700 transition-colors">
                <RefreshCw size={20} className="text-slate-300" />
            </button>
        </div>
        <div className="bg-slate-800 rounded-lg shadow-lg overflow-x-auto">
            <table className="min-w-full text-white">
                <thead className="bg-slate-900">
                    <tr>
                        {['ID Agent', 'Hostname', 'OS', 'IP', 'Dernière Connexion'].map(h => 
                            <th key={h} className="text-left py-3 px-4 uppercase font-semibold text-sm">{h}</th>
                        )}
                    </tr>
                </thead>
                <tbody className="divide-y divide-slate-700">
                    {agents.map(agent => (
                        <tr key={agent.id} className="hover:bg-slate-700/50">
                            <td className="py-3 px-4 font-mono text-xs">{agent.id}</td>
                            <td className="py-3 px-4">{agent.hostname}</td>
                            <td className="py-3 px-4">{agent.os}</td>
                            <td className="py-3 px-4 font-mono">{agent.ip}</td>
                            <td className="py-3 px-4">{new Date(agent.last_seen).toLocaleString()}</td>
                        </tr>
                    ))}
                </tbody>
            </table>
        </div>
    </>
);

const HuntView = ({ agents }) => {
    const [selectedAgent, setSelectedAgent] = useState('');
    const [query, setQuery] = useState('SELECT * FROM processes;');
    const [status, setStatus] = useState({ message: '', type: '' });

    useEffect(() => {
        if (agents.length > 0 && !selectedAgent) {
            setSelectedAgent(agents[0].id);
        }
    }, [agents, selectedAgent]);
    
    const handleSubmit = async (e) => {
        e.preventDefault();
        if (!selectedAgent) {
            setStatus({ message: 'Veuillez sélectionner un agent.', type: 'error' });
            return;
        }
        setStatus({ message: 'Envoi de la requête...', type: 'info' });
        try {
            const result = await submitQuery(selectedAgent, query);
            setStatus({ message: `Requête soumise avec succès (ID: ${result.query_id})`, type: 'success' });
        } catch (error) {
            setStatus({ message: `Erreur: ${error.message}`, type: 'error' });
        }
    };

    return (
        <>
            <h2 className="text-3xl font-bold text-white mb-6">Lancer une Investigation (Hunt)</h2>
            <form onSubmit={handleSubmit} className="bg-slate-800 p-8 rounded-lg shadow-lg">
                <div className="mb-6">
                    <label htmlFor="agent-select" className="block text-slate-300 mb-2">Cibler un Agent</label>
                    <select
                        id="agent-select"
                        value={selectedAgent}
                        onChange={e => setSelectedAgent(e.target.value)}
                        className="w-full bg-slate-700 text-white p-3 rounded-md border border-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    >
                        <option value="" disabled>Sélectionnez un agent...</option>
                        {agents.map(agent => (
                            <option key={agent.id} value={agent.id}>{agent.hostname} ({agent.id.substring(0,8)}...)</option>
                        ))}
                    </select>
                </div>
                <div className="mb-6">
                    <label htmlFor="oql-query" className="block text-slate-300 mb-2">Requête OQL</label>
                    <textarea
                        id="oql-query"
                        value={query}
                        onChange={e => setQuery(e.target.value)}
                        className="w-full h-48 bg-slate-900 text-cyan-300 font-mono p-4 rounded-md border border-slate-600 focus:outline-none focus:ring-2 focus:ring-blue-500"
                        placeholder="SELECT * FROM ..."
                    />
                </div>
                <div className="flex justify-between items-center">
                    <button type="submit" className="flex items-center bg-blue-600 hover:bg-blue-700 text-white font-bold py-2 px-4 rounded-md transition-colors">
                        <Send size={18} className="mr-2"/>
                        Lancer la Requête
                    </button>
                    {status.message && (
                        <p className={`text-sm ${
                            status.type === 'success' ? 'text-green-400' :
                            status.type === 'error' ? 'text-red-400' :
                            'text-slate-400'
                        }`}>{status.message}</p>
                    )}
                </div>
            </form>
        </>
    )
};

// --- Composant Principal de l'Application ---
export default function App() {
  const [activeView, setActiveView] = useState('dashboard');
  const [agents, setAgents] = useState([]);
  
  const refreshAgents = () => {
      fetchAgents().then(setAgents);
  };
  
  useEffect(() => {
      refreshAgents();
      const interval = setInterval(refreshAgents, 10000); // Rafraîchit toutes les 10 secondes
      return () => clearInterval(interval);
  }, []);
  
  const NavItem = ({ viewName, icon, label }) => (
      <li onClick={() => setActiveView(viewName)} className={`flex items-center p-3 my-1 rounded-lg cursor-pointer transition-colors ${activeView === viewName ? 'bg-blue-600 text-white' : 'text-slate-300 hover:bg-slate-700'}`}>
        {icon}
        <span className="ml-4 font-medium">{label}</span>
      </li>
  );
  
  const renderView = () => {
      switch(activeView) {
          case 'dashboard': return <Dashboard agentCount={agents.length} />;
          case 'agents': return <AgentsView agents={agents} onRefresh={refreshAgents} />;
          case 'hunt': return <HuntView agents={agents}/>;
          default: return <Dashboard agentCount={agents.length} />;
      }
  };

  return (
    <div className="flex h-screen bg-slate-900 font-sans">
      <nav className="w-64 bg-slate-800/50 p-5 flex flex-col shrink-0">
        <div className="flex items-center mb-10">
          <Shield size={32} className="text-blue-400" />
          <h1 className="text-white text-2xl font-bold ml-3">Osiris</h1>
        </div>
        <ul>
          <NavItem viewName="dashboard" icon={<Home size={20} />} label="Tableau de Bord" />
          <NavItem viewName="agents" icon={<Server size={20} />} label="Agents" />
          <NavItem viewName="hunt" icon={<ChevronsRight size={20} />} label="Investigation" />
        </ul>
        <div className="mt-auto text-slate-500 text-xs">
            Version 0.3.0 (Phase 3)
        </div>
      </nav>

      <main className="flex-1 p-10 overflow-y-auto">
        {renderView()}
      </main>
    </div>
  );
} 