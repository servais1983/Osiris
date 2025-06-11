import { useState, useEffect, useRef } from 'react';
import { Search, AlertCircle, CheckCircle, XCircle } from 'lucide-react';

export default function Hunt() {
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [isSearching, setIsSearching] = useState(false);
  const [error, setError] = useState(null);
  const wsRef = useRef(null);

  useEffect(() => {
    // Connexion au WebSocket
    wsRef.current = new WebSocket('ws://localhost:8002/ws/hunt');

    wsRef.current.onmessage = (event) => {
      const data = JSON.parse(event.data);
      if (data.type === 'result') {
        setResults(prev => [...prev, data.result]);
      } else if (data.type === 'complete') {
        setIsSearching(false);
      } else if (data.type === 'error') {
        setError(data.message);
        setIsSearching(false);
      }
    };

    wsRef.current.onerror = (error) => {
      setError('Erreur de connexion WebSocket');
      setIsSearching(false);
    };

    return () => {
      if (wsRef.current) {
        wsRef.current.close();
      }
    };
  }, []);

  const handleSearch = async (e) => {
    e.preventDefault();
    if (!query.trim()) return;

    setResults([]);
    setError(null);
    setIsSearching(true);

    try {
      const response = await fetch('/api/hunt', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ query: query.trim() }),
      });

      if (!response.ok) {
        throw new Error('Erreur lors de l\'envoi de la requête');
      }
    } catch (err) {
      setError(err.message);
      setIsSearching(false);
    }
  };

  return (
    <div className="space-y-6">
      <form onSubmit={handleSearch} className="flex gap-4">
        <div className="flex-1">
          <label htmlFor="query" className="sr-only">
            Requête de recherche
          </label>
          <div className="relative rounded-md shadow-sm">
            <div className="absolute inset-y-0 left-0 pl-3 flex items-center pointer-events-none">
              <Search className="h-5 w-5 text-gray-400" />
            </div>
            <input
              type="text"
              name="query"
              id="query"
              className="block w-full pl-10 pr-3 py-2 border border-gray-300 rounded-md leading-5 bg-white placeholder-gray-500 focus:outline-none focus:placeholder-gray-400 focus:ring-1 focus:ring-indigo-500 focus:border-indigo-500 sm:text-sm"
              placeholder="Entrez votre requête OQL..."
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              disabled={isSearching}
            />
          </div>
        </div>
        <button
          type="submit"
          disabled={isSearching || !query.trim()}
          className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {isSearching ? 'Recherche...' : 'Rechercher'}
        </button>
      </form>

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

      <div className="space-y-4">
        {results.map((result, index) => (
          <div
            key={index}
            className="bg-white shadow rounded-lg p-4"
          >
            <div className="flex items-start">
              <div className="flex-shrink-0">
                {result.status === 'success' ? (
                  <CheckCircle className="h-5 w-5 text-green-400" />
                ) : (
                  <XCircle className="h-5 w-5 text-red-400" />
                )}
              </div>
              <div className="ml-3 flex-1">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-medium text-gray-900">
                    {result.agent_id}
                  </h3>
                  <span className="text-xs text-gray-500">
                    {new Date(result.timestamp).toLocaleString()}
                  </span>
                </div>
                <div className="mt-2 text-sm text-gray-500">
                  <pre className="whitespace-pre-wrap">{result.message}</pre>
                </div>
                {result.details && (
                  <div className="mt-2">
                    <pre className="bg-gray-50 p-2 rounded text-xs overflow-x-auto">
                      {JSON.stringify(result.details, null, 2)}
                    </pre>
                  </div>
                )}
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
} 