"""
Source OQL pour les utilisateurs Linux
"""

import logging
from typing import Dict, List, Any
from collectors.linux import UsersCollector

logger = logging.getLogger(__name__)

class LinuxUsersSource:
    """Source OQL pour les utilisateurs Linux"""
    
    def __init__(self, include_shadow: bool = True):
        self.include_shadow = include_shadow
        self.collector = UsersCollector()
    
    def collect(self) -> List[Dict[str, Any]]:
        """Collecte les utilisateurs Linux"""
        try:
            results = self.collector.collect()
            
            all_users = []
            
            # Utilisateurs de base
            for user in results.get('users', []):
                user['source'] = 'linux_users'
                all_users.append(user)
            
            # Utilisateurs suspects
            for suspicious_user in results.get('suspicious_users', []):
                user_info = suspicious_user.get('user_info', {})
                user_info['suspicious_flags'] = suspicious_user.get('suspicious_flags', [])
                user_info['risk_level'] = suspicious_user.get('risk_level', 'unknown')
                user_info['source'] = 'linux_users'
                user_info['is_suspicious'] = True
                all_users.append(user_info)
            
            # Utilisateurs privilégiés
            for privileged_user in results.get('privileged_users', []):
                user_info = privileged_user.get('user_info', {})
                user_info['privileges'] = privileged_user.get('privileges', [])
                user_info['source'] = 'linux_users'
                user_info['is_privileged'] = True
                all_users.append(user_info)
            
            return all_users
            
        except Exception as e:
            logger.error(f"Erreur lors de la collecte des utilisateurs: {e}")
            return [] 