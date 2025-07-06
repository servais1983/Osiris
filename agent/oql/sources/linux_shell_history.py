"""
Source OQL pour l'historique shell Linux
"""

import logging
from typing import Dict, List, Any, Optional
from collectors.linux import ShellHistoryCollector

logger = logging.getLogger(__name__)

class LinuxShellHistorySource:
    """Source OQL pour l'historique shell Linux"""
    
    def __init__(self, username: Optional[str] = None, shell_type: Optional[str] = None):
        self.username = username
        self.shell_type = shell_type
        self.collector = ShellHistoryCollector()
    
    def collect(self) -> List[Dict[str, Any]]:
        """Collecte l'historique shell Linux"""
        try:
            results = self.collector.collect()
            
            all_commands = []
            
            # Historique de l'utilisateur actuel
            current_user_history = results.get('current_user_history', {})
            for shell_file, shell_data in current_user_history.get('shell_files', {}).items():
                if isinstance(shell_data, dict) and 'commands' in shell_data:
                    for command in shell_data['commands']:
                        command['source'] = 'current_user'
                        command['shell_file'] = shell_file
                        command['username'] = current_user_history.get('username', 'unknown')
                        all_commands.append(command)
            
            # Historique de tous les utilisateurs (si root)
            all_users_history = results.get('all_users_history', {})
            for username, user_history in all_users_history.items():
                for shell_file, shell_data in user_history.get('shell_files', {}).items():
                    if isinstance(shell_data, dict) and 'commands' in shell_data:
                        for command in shell_data['commands']:
                            command['source'] = 'all_users'
                            command['shell_file'] = shell_file
                            command['username'] = username
                            all_commands.append(command)
            
            # Filtrer par utilisateur si spécifié
            if self.username:
                all_commands = [cmd for cmd in all_commands if cmd.get('username') == self.username]
            
            # Filtrer par type de shell si spécifié
            if self.shell_type:
                all_commands = [cmd for cmd in all_commands if self.shell_type in cmd.get('shell_file', '')]
            
            # Trier par timestamp si disponible
            all_commands.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
            
            return all_commands
            
        except Exception as e:
            logger.error(f"Erreur lors de la collecte de l'historique shell: {e}")
            return [] 