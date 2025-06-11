import { useState, useEffect } from 'react';
import { AlertCircle, Server, Search, FolderOpen, Activity } from 'lucide-react';
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer
} from 'recharts';

export default function Dashboard() {
  const [stats, setStats] = useState({
    agents: { total: 0, online: 0 },
    alerts: { total: 0, critical: 0 },
    cases: { total: 0, open: 0 },
    events: { total: 0, last24h: 0 }
  });
  const [error, setError] = useState(null);
  const [activityData, setActivityData] = useState([]);

  useEffect(() => {
    fetchStats();
    fetchActivityData();
    const interval = setInterval(() => {
      fetchStats();
      fetchActivityData();
    }, 30000);
    return () => clearInterval(interval);
  }, []);

  const fetchStats = async () => {
    try {
      const response = await fetch('/api/stats');
      const data = await response.json();
      setStats(data);
      setError(null);
    } catch (err) {
      setError('Impossible de charger les statistiques');
      console.error('Erreur lors du chargement des statistiques:', err);
    }
  };

  const fetchActivityData = async () => {
    try {
      const response = await fetch('/api/stats/activity');
      const data = await response.json();
      setActivityData(data);
    } catch (err) {
      console.error('Erreur lors du chargement des données d\'activité:', err);
    }
  };

  const statCards = [
    {
      name: 'Agents',
      value: stats.agents.total,
      subValue: `${stats.agents.online} en ligne`,
      icon: Server,
      color: 'bg-blue-500'
    },
    {
      name: 'Alertes',
      value: stats.alerts.total,
      subValue: `${stats.alerts.critical} critiques`,
      icon: AlertCircle,
      color: 'bg-red-500'
    },
    {
      name: 'Cas',
      value: stats.cases.total,
      subValue: `${stats.cases.open} ouverts`,
      icon: FolderOpen,
      color: 'bg-green-500'
    },
    {
      name: 'Événements',
      value: stats.events.total,
      subValue: `${stats.events.last24h} dernières 24h`,
      icon: Activity,
      color: 'bg-purple-500'
    }
  ];

  return (
    <div className="space-y-6">
      <h2 className="text-lg font-medium text-gray-900">Tableau de bord</h2>

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

      <div className="grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
        {statCards.map((stat) => {
          const Icon = stat.icon;
          return (
            <div
              key={stat.name}
              className="bg-white overflow-hidden shadow rounded-lg"
            >
              <div className="p-5">
                <div className="flex items-center">
                  <div className={`flex-shrink-0 rounded-md p-3 ${stat.color}`}>
                    <Icon className="h-6 w-6 text-white" />
                  </div>
                  <div className="ml-5 w-0 flex-1">
                    <dl>
                      <dt className="text-sm font-medium text-gray-500 truncate">
                        {stat.name}
                      </dt>
                      <dd>
                        <div className="text-lg font-medium text-gray-900">
                          {stat.value}
                        </div>
                        <div className="text-sm text-gray-500">
                          {stat.subValue}
                        </div>
                      </dd>
                    </dl>
                  </div>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      <div className="bg-white shadow rounded-lg p-6">
        <h3 className="text-lg font-medium text-gray-900 mb-4">
          Activité des 7 derniers jours
        </h3>
        <div className="h-80">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart
              data={activityData}
              margin={{
                top: 5,
                right: 30,
                left: 20,
                bottom: 5,
              }}
            >
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis
                dataKey="date"
                tickFormatter={(value) => new Date(value).toLocaleDateString('fr-FR', { weekday: 'short' })}
              />
              <YAxis />
              <Tooltip
                labelFormatter={(value) => new Date(value).toLocaleDateString('fr-FR', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' })}
              />
              <Bar dataKey="events" name="Événements" fill="#6366F1" />
              <Bar dataKey="alerts" name="Alertes" fill="#EF4444" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="grid gap-6 sm:grid-cols-2">
        <div className="bg-white shadow rounded-lg p-6">
          <h3 className="text-lg font-medium text-gray-900 mb-4">
            Dernières alertes
          </h3>
          <div className="space-y-4">
            {/* TODO: Implémenter la liste des dernières alertes */}
          </div>
        </div>

        <div className="bg-white shadow rounded-lg p-6">
          <h3 className="text-lg font-medium text-gray-900 mb-4">
            Cas récents
          </h3>
          <div className="space-y-4">
            {/* TODO: Implémenter la liste des cas récents */}
          </div>
        </div>
      </div>
    </div>
  );
} 