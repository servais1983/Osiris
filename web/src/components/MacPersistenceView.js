import React, { useState, useEffect } from 'react';

// Composant pour afficher les données de persistance macOS
function MacPersistenceView() {
  const [persistenceItems, setPersistenceItems] = useState([]);
  const [loading, setLoading] = useState(true);

  // Hook pour charger les données au montage du composant
  useEffect(() => {
    // Ici, on appellerait l'API du "Hive" d'Osiris
    // fetch('/api/v1/data/macos_persistence')
    //   .then(res => res.json())
    //   .then(data => {
    //     setPersistenceItems(data);
    //     setLoading(false);
    //   });

    // Pour l'exemple, on utilise des données statiques :
    const mockData = [
      { path: '/Library/LaunchDaemons/com.malware.plist', program: '/tmp/evil.sh', type: 'Global Daemon', run_at_load: true },
      { path: '/Users/test/Library/LaunchAgents/com.google.keystone.agent.plist', program: '~/Library/Google/GoogleSoftwareUpdate/...', type: 'User Agent', run_at_load: true },
    ];
    setPersistenceItems(mockData);
    setLoading(false);
  }, []);

  if (loading) {
    return <div>Chargement des données de persistance...</div>;
  }

  return (
    <div className="view-container">
      <h2>Persistance macOS</h2>
      <table>
        <thead>
          <tr>
            <th>Programme</th>
            <th>Type</th>
            <th>Chemin du fichier .plist</th>
            <th>Lancement au démarrage</th>
          </tr>
        </thead>
        <tbody>
          {persistenceItems.map((item, index) => (
            <tr key={index} className={!item.path.startsWith('/System/') ? 'suspicious' : ''}>
              <td>{item.program}</td>
              <td>{item.type}</td>
              <td>{item.path}</td>
              <td>{item.run_at_load ? 'Oui' : 'Non'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export default MacPersistenceView; 