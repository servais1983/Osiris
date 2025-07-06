import os
import subprocess
import logging
from typing import List, Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)

class ShellHistoryCollector:
    """Collecte l'historique des shells Linux."""
    
    def __init__(self):
        self.shell_files = [
            '.bash_history',
            '.zsh_history',
            '.fish_history'
        ]
    
    def collect(self) -> List[Dict[str, Any]]:
        """Collecte l'historique de tous les shells disponibles."""
        results = []
        
        for shell_file in self.shell_files:
            try:
                shell_results = self._collect_shell_history(shell_file)
                results.extend(shell_results)
            except Exception as e:
                logger.error(f"Error collecting {shell_file}: {e}")
        
        return results
    
    def _collect_shell_history(self, shell_file: str) -> List[Dict[str, Any]]:
        """Collecte l'historique d'un shell spécifique."""
        results = []
        home_dir = os.path.expanduser('~')
        history_path = os.path.join(home_dir, shell_file)
        
        if not os.path.exists(history_path):
            return results
        
        try:
            with open(history_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            for i, line in enumerate(lines):
                line = line.strip()
                if line:
                    results.append({
                        'type': 'shell_history',
                        'shell_file': shell_file,
                        'command': line,
                        'line_number': i + 1,
                        'timestamp': datetime.now().isoformat(),
                        'user': os.getenv('USER', 'unknown')
                    })
        
        except Exception as e:
            logger.error(f"Error reading {history_path}: {e}")
        
        return results
    
    def get_recent_commands(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Récupère les commandes récentes."""
        # Cette méthode pourrait être améliorée pour utiliser les timestamps
        # si disponibles dans les fichiers d'historique
        return self.collect() 