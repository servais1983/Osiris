"""
Source OQL pour les processus Linux
"""

import logging
from typing import Dict, List, Any
from collectors.linux import ProcessesCollector

logger = logging.getLogger(__name__)

class LinuxProcessesSource:
    """Source OQL pour les processus Linux"""
    
    def __init__(self):
        self.collector = ProcessesCollector()
    
    def collect(self) -> List[Dict[str, Any]]:
        """Collecte les processus Linux"""
        try:
            results = self.collector.collect()
            
            # Retourner tous les processus
            processes = results.get('processes', [])
            
            # Ajouter des métadonnées
            for process in processes:
                process['source'] = 'linux_processes'
                process['collection_time'] = results.get('system_info', {}).get('timestamp', '')
            
            return processes
            
        except Exception as e:
            logger.error(f"Erreur lors de la collecte des processus: {e}")
            return [] 