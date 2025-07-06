"""
Collecteurs Linux pour Osiris
Fournit des collecteurs pour les artefacts forensiques Linux
"""

import logging
from typing import Dict, List, Any
from .base import LinuxCollector
from .system_logs import SystemLogsCollector
from .shell_history import ShellHistoryCollector
from .processes import ProcessesCollector
from .network import NetworkCollector
from .files import FilesCollector
from .services import ServicesCollector
from .users import UsersCollector
from .cron_jobs import CronJobsCollector
from .systemd_services import SystemdServicesCollector

logger = logging.getLogger(__name__)

class LinuxCollectorManager:
    """Gestionnaire des collecteurs Linux"""
    
    def __init__(self):
        self.collectors = {
            'system_logs': SystemLogsCollector,
            'shell_history': ShellHistoryCollector,
            'processes': ProcessesCollector,
            'network': NetworkCollector,
            'files': FilesCollector,
            'services': ServicesCollector,
            'users': UsersCollector,
            'cron_jobs': CronJobsCollector,
            'systemd_services': SystemdServicesCollector
        }
    
    def get_collector(self, name: str) -> LinuxCollector:
        """Retourne une instance du collecteur demandé"""
        if name not in self.collectors:
            raise ValueError(f"Collecteur inconnu: {name}")
        
        return self.collectors[name]()
    
    def list_collectors(self) -> List[str]:
        """Retourne la liste des collecteurs disponibles"""
        return list(self.collectors.keys())
    
    def collect_all(self) -> Dict[str, Any]:
        """Exécute tous les collecteurs et retourne les résultats"""
        results = {}
        
        for name, collector_class in self.collectors.items():
            try:
                logger.info(f"Exécution du collecteur: {name}")
                collector = collector_class()
                results[name] = collector.collect()
            except Exception as e:
                logger.error(f"Erreur lors de l'exécution du collecteur {name}: {e}")
                results[name] = {'error': str(e)}
        
        return results

# Export des classes principales
__all__ = [
    'LinuxCollector',
    'SystemLogsCollector',
    'ShellHistoryCollector', 
    'ProcessesCollector',
    'NetworkCollector',
    'FilesCollector',
    'ServicesCollector',
    'UsersCollector',
    'CronJobsCollector',
    'SystemdServicesCollector',
    'LinuxCollectorManager'
] 