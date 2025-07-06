"""
Source OQL pour les logs système Linux
"""

import logging
from typing import Dict, List, Any, Optional
from collectors.linux import SystemLogsCollector

logger = logging.getLogger(__name__)

class LinuxSystemLogsSource:
    """Source OQL pour les logs système Linux"""
    
    def __init__(self, log_file: Optional[str] = None, max_lines: int = 1000):
        self.log_file = log_file
        self.max_lines = max_lines
        self.collector = SystemLogsCollector()
    
    def collect(self) -> List[Dict[str, Any]]:
        """Collecte les logs système Linux"""
        try:
            results = self.collector.collect()
            
            # Si un fichier spécifique est demandé
            if self.log_file:
                if self.log_file in results.get('log_files', {}):
                    log_data = results['log_files'][self.log_file]
                    return log_data.get('recent_entries', [])[:self.max_lines]
                else:
                    logger.warning(f"Fichier de log {self.log_file} non trouvé")
                    return []
            
            # Retourner tous les logs récents
            all_logs = []
            
            # Logs système
            for log_file, log_data in results.get('log_files', {}).items():
                if isinstance(log_data, dict) and 'recent_entries' in log_data:
                    for entry in log_data['recent_entries']:
                        entry['source_file'] = log_file
                        all_logs.append(entry)
            
            # Logs dmesg
            dmesg_data = results.get('dmesg', {})
            if isinstance(dmesg_data, dict) and 'recent_entries' in dmesg_data:
                for entry in dmesg_data['recent_entries']:
                    entry['source'] = 'dmesg'
                    all_logs.append(entry)
            
            # Logs journalctl
            journalctl_data = results.get('journalctl', {})
            if isinstance(journalctl_data, dict) and 'recent_entries' in journalctl_data:
                for entry in journalctl_data['recent_entries']:
                    entry['source'] = 'journalctl'
                    all_logs.append(entry)
            
            return all_logs[:self.max_lines]
            
        except Exception as e:
            logger.error(f"Erreur lors de la collecte des logs système: {e}")
            return [] 