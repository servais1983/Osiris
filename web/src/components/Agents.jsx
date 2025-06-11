import { useState, useEffect } from 'react';
import { AlertCircle, Server, Clock, Link as LinkIcon } from 'lucide-react';
import { format } from 'date-fns';
import { fr } from 'date-fns/locale';

export default function Agents() {
  const [agents, setAgents] = useState([]);
  const [error, setError] = useState(null);

  useEffect(() => {
    fetchAgents();
    const interval = setInterval(fetchAgents, 5000);
    return () => clearInterval(interval);
  }, []);

  const fetchAgents = async () => {
    try {
      const response = await fetch('/api/agents');
      const data = await response.json();
      setAgents(data.agents);
      setError(null);
    } catch (err) {
      setError('Impossible de charger la liste des agents');
      console.error('Erreur lors du chargement des agents:', err);
    }
  };

  const getStatusColor = (status) => {
    const colors = {
      online: 'bg-green-100 text-green-800',
      offline: 'bg-red-100 text-red-800',
      warning: 'bg-yellow-100 text-yellow-800'
    };
    return colors[status] || colors.offline;
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <h2 className="text-lg font-medium text-gray-900">Agents</h2>
        <div className="text-sm text-gray-500">
          {agents.length} agent{agents.length !== 1 ? 's' : ''} connecté{agents.length !== 1 ? 's' : ''}
        </div>
      </div>

      {error && (
        <div className="rounded-md bg-red-50 p-4">
          <div className="flex">
            <div className="flex-shrink-0">
              <AlertCircle className="h-5 w-5 text-red-400" />
            </div>
            <div className="ml-3">
              <h3 className="text-sm font-medium text-red-800">{error}</h3>
            </div>
          </div>
        </div>
      )}

      <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-3">
        {agents.map((agent) => (
          <div
            key={agent.agent_id}
            className="bg-white shadow rounded-lg overflow-hidden"
          >
            <div className="p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center">
                  <Server className="h-5 w-5 text-gray-400 mr-2" />
                  <h3 className="text-lg font-medium text-gray-900">
                    {agent.hostname}
                  </h3>
                </div>
                <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${getStatusColor(agent.status)}`}>
                  {agent.status}
                </span>
              </div>

              <dl className="grid grid-cols-1 gap-x-4 gap-y-4 sm:grid-cols-2">
                <div>
                  <dt className="text-sm font-medium text-gray-500">ID</dt>
                  <dd className="mt-1 text-sm text-gray-900">{agent.agent_id}</dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500">IP</dt>
                  <dd className="mt-1 text-sm text-gray-900">{agent.ip_address || 'N/A'}</dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500">Système</dt>
                  <dd className="mt-1 text-sm text-gray-900">{agent.os_info || 'N/A'}</dd>
                </div>
                <div>
                  <dt className="text-sm font-medium text-gray-500">Version</dt>
                  <dd className="mt-1 text-sm text-gray-900">{agent.version || 'N/A'}</dd>
                </div>
              </dl>

              <div className="mt-4 flex items-center justify-between text-sm text-gray-500">
                <div className="flex items-center">
                  <Clock className="h-4 w-4 mr-1" />
                  {format(new Date(agent.last_seen), 'PPpp', { locale: fr })}
                </div>
                <div className="flex items-center">
                  <LinkIcon className="h-4 w-4 mr-1" />
                  {agent.connection_type || 'N/A'}
                </div>
              </div>
            </div>

            <div className="bg-gray-50 px-6 py-3">
              <div className="flex justify-end space-x-3">
                <button
                  onClick={() => {/* TODO: Implémenter la navigation vers la timeline */}}
                  className="inline-flex items-center px-3 py-1.5 border border-gray-300 shadow-sm text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                >
                  Timeline
                </button>
                <button
                  onClick={() => {/* TODO: Implémenter la navigation vers les détails */}}
                  className="inline-flex items-center px-3 py-1.5 border border-transparent text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
                >
                  Détails
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
} 