"""
Source OQL pour les fichiers Linux
"""

import logging
from typing import Dict, List, Any
from collectors.linux import FilesCollector

logger = logging.getLogger(__name__)

class LinuxFilesSource:
    """Source OQL pour les fichiers Linux"""
    
    def __init__(self, path: str):
        self.path = path
        self.collector = FilesCollector()
    
    def collect(self) -> List[Dict[str, Any]]:
        """Collecte les informations sur les fichiers Linux"""
        try:
            # Pour l'instant, on utilise le collecteur général
            # Dans une version future, on pourrait implémenter une collecte spécifique par chemin
            results = self.collector.collect()
            
            all_files = []
            
            # Fichiers récents
            for file_info in results.get('recent_files', []):
                if self.path in file_info.get('path', ''):
                    file_info['source'] = 'linux_files'
                    file_info['search_path'] = self.path
                    all_files.append(file_info)
            
            # Fichiers importants
            for file_path, file_data in results.get('important_files', {}).items():
                if self.path in file_path:
                    if isinstance(file_data, dict) and 'file_info' in file_data:
                        file_data['file_info']['source'] = 'linux_files'
                        file_data['file_info']['search_path'] = self.path
                        all_files.append(file_data['file_info'])
            
            return all_files
            
        except Exception as e:
            logger.error(f"Erreur lors de la collecte des fichiers: {e}")
            return [] 