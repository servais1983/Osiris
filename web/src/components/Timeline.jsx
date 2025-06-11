import { useState, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { format } from 'date-fns';
import { fr } from 'date-fns/locale';
import { AlertCircle, Info } from 'lucide-react';

const EVENT_BADGES = {
  'Process Start': 'bg-blue-100 text-blue-800',
  'File Modified': 'bg-green-100 text-green-800',
  'Program Execution': 'bg-yellow-100 text-yellow-800',
  'Program Execution Evidence': 'bg-indigo-100 text-indigo-800',
  'Network Connection': 'bg-red-100 text-red-800',
  'YARA Match': 'bg-gray-100 text-gray-800'
};

const SIGMA_LEVELS = {
  'critical': 'bg-red-100 text-red-800',
  'high': 'bg-orange-100 text-orange-800',
  'medium': 'bg-yellow-100 text-yellow-800',
  'low': 'bg-gray-100 text-gray-800'
};

function EventBadge({ type }) {
  const className = EVENT_BADGES[type] || 'bg-gray-100 text-gray-800';
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${className}`}>
      {type}
    </span>
  );
}

function SigmaBadge({ level }) {
  const className = SIGMA_LEVELS[level.toLowerCase()] || 'bg-gray-100 text-gray-800';
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${className}`}>
      Sigma: {level}
    </span>
  );
}

function EventDetails({ event, onClose }) {
  if (!event) return null;

  return (
    <div className="fixed inset-0 bg-gray-500 bg-opacity-75 flex items-center justify-center p-4">
      <div className="bg-white rounded-lg max-w-4xl w-full max-h-[90vh] overflow-y-auto">
        <div className="p-6">
          <div className="flex justify-between items-start mb-4">
            <h3 className="text-lg font-medium text-gray-900">Détails de l'événement</h3>
            <button
              onClick={onClose}
              className="text-gray-400 hover:text-gray-500"
            >
              <span className="sr-only">Fermer</span>
              <svg className="h-6 w-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          </div>

          <dl className="grid grid-cols-1 gap-x-4 gap-y-6 sm:grid-cols-2">
            <div>
              <dt className="text-sm font-medium text-gray-500">Horodatage</dt>
              <dd className="mt-1 text-sm text-gray-900">
                {format(new Date(event.timestamp), 'PPpp', { locale: fr })}
              </dd>
            </div>
            <div>
              <dt className="text-sm font-medium text-gray-500">Source</dt>
              <dd className="mt-1 text-sm text-gray-900">{event.source}</dd>
            </div>
            <div>
              <dt className="text-sm font-medium text-gray-500">Type</dt>
              <dd className="mt-1 text-sm text-gray-900">{event.event_type}</dd>
            </div>
            <div>
              <dt className="text-sm font-medium text-gray-500">Résumé</dt>
              <dd className="mt-1 text-sm text-gray-900">{event.summary}</dd>
            </div>
          </dl>

          <div className="mt-6">
            <h4 className="text-sm font-medium text-gray-900">Détails</h4>
            <pre className="mt-2 bg-gray-50 p-4 rounded-lg overflow-x-auto">
              <code>{JSON.stringify(event.details, null, 2)}</code>
            </pre>
          </div>

          {event.sigma_matches && event.sigma_matches.length > 0 && (
            <div className="mt-6">
              <h4 className="text-sm font-medium text-gray-900 mb-4">Détections Sigma</h4>
              <div className="space-y-4">
                {event.sigma_matches.map((rule, index) => (
                  <div key={index} className="bg-gray-50 rounded-lg p-4">
                    <div className="flex justify-between items-start mb-2">
                      <h5 className="text-sm font-medium text-gray-900">{rule.title}</h5>
                      <SigmaBadge level={rule.level} />
                    </div>
                    <p className="text-sm text-gray-500 mb-4">{rule.description}</p>
                    <dl className="grid grid-cols-1 gap-x-4 gap-y-2 sm:grid-cols-2">
                      <div>
                        <dt className="text-xs font-medium text-gray-500">ID</dt>
                        <dd className="mt-1 text-xs text-gray-900">{rule.id}</dd>
                      </div>
                      <div>
                        <dt className="text-xs font-medium text-gray-500">Auteur</dt>
                        <dd className="mt-1 text-xs text-gray-900">{rule.author || 'N/A'}</dd>
                      </div>
                      <div>
                        <dt className="text-xs font-medium text-gray-500">Date</dt>
                        <dd className="mt-1 text-xs text-gray-900">{rule.date || 'N/A'}</dd>
                      </div>
                      <div>
                        <dt className="text-xs font-medium text-gray-500">Tags</dt>
                        <dd className="mt-1 text-xs text-gray-900">
                          {rule.tags?.join(', ') || 'Aucun'}
                        </dd>
                      </div>
                    </dl>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default function Timeline() {
  const { agentId } = useParams();
  const [events, setEvents] = useState([]);
  const [selectedEvent, setSelectedEvent] = useState(null);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchTimeline = async () => {
      try {
        const response = await fetch(`/api/timeline/${agentId}`);
        const data = await response.json();
        setEvents(data.timeline);
        setError(null);
      } catch (err) {
        setError('Impossible de charger la timeline');
        console.error('Erreur lors du chargement de la timeline:', err);
      }
    };

    fetchTimeline();
    const interval = setInterval(fetchTimeline, 5000);
    return () => clearInterval(interval);
  }, [agentId]);

  if (error) {
    return (
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
    );
  }

  return (
    <div className="space-y-4">
      {events.map((event, index) => (
        <div
          key={event.timestamp}
          className={`bg-white shadow rounded-lg p-4 ${
            event.sigma_matches?.length > 0 ? 'border-l-4 border-red-500' : ''
          }`}
        >
          <div className="flex items-start justify-between">
            <div className="flex-1">
              <div className="flex items-center space-x-2 mb-2">
                <EventBadge type={event.event_type} />
                <span className="text-sm text-gray-500">{event.source}</span>
                {event.sigma_matches?.map((rule, i) => (
                  <SigmaBadge key={i} level={rule.level} />
                ))}
              </div>
              <p className="text-sm text-gray-900">{event.summary}</p>
              <p className="text-xs text-gray-500 mt-1">
                {format(new Date(event.timestamp), 'PPpp', { locale: fr })}
              </p>
            </div>
            <button
              onClick={() => setSelectedEvent(event)}
              className="ml-4 inline-flex items-center px-2.5 py-1.5 border border-gray-300 shadow-sm text-xs font-medium rounded text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500"
            >
              <Info className="h-4 w-4 mr-1" />
              Détails
            </button>
          </div>
        </div>
      ))}

      {selectedEvent && (
        <EventDetails
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
        />
      )}
    </div>
  );
} 