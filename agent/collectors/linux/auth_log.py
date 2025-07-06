import subprocess
import logging
from typing import List, Dict, Any
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class AuthLogCollector:
    """Collecte les logs d'authentification Linux."""
    
    def __init__(self):
        self.log_files = [
            '/var/log/auth.log',
            '/var/log/secure',
            '/var/log/messages'
        ]
    
    def collect(self, hours_back: int = 24) -> List[Dict[str, Any]]:
        """Collecte les logs d'authentification récents."""
        results = []
        
        for log_file in self.log_files:
            try:
                log_results = self._collect_auth_log(log_file, hours_back)
                results.extend(log_results)
            except Exception as e:
                logger.error(f"Error collecting from {log_file}: {e}")
        
        return results
    
    def _collect_auth_log(self, log_file: str, hours_back: int) -> List[Dict[str, Any]]:
        """Collecte les logs d'un fichier spécifique."""
        results = []
        
        try:
            # Utiliser journalctl pour les logs système modernes
            if log_file == '/var/log/messages':
                cmd = [
                    'journalctl', 
                    '--since', f'{hours_back}h ago',
                    '--no-pager',
                    'SYSLOG_FACILITY=10'  # auth facility
                ]
            else:
                # Pour les fichiers de log traditionnels
                cmd = [
                    'tail', 
                    '-n', '1000', 
                    log_file
                ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                lines = result.stdout.splitlines()
                
                for line in lines:
                    if self._is_auth_line(line):
                        parsed = self._parse_auth_line(line)
                        if parsed:
                            results.append(parsed)
        
        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout collecting from {log_file}")
        except Exception as e:
            logger.error(f"Error running command for {log_file}: {e}")
        
        return results
    
    def _is_auth_line(self, line: str) -> bool:
        """Détermine si une ligne contient des informations d'authentification."""
        auth_keywords = [
            'authentication failure',
            'authentication success',
            'login',
            'logout',
            'ssh',
            'su:',
            'sudo:',
            'pam_',
            'password'
        ]
        
        line_lower = line.lower()
        return any(keyword in line_lower for keyword in auth_keywords)
    
    def _parse_auth_line(self, line: str) -> Dict[str, Any]:
        """Parse une ligne de log d'authentification."""
        try:
            # Parse basique - peut être amélioré selon le format exact
            parts = line.split()
            
            if len(parts) < 4:
                return None
            
            # Extraire la date et l'heure
            date_str = ' '.join(parts[:3])
            
            # Identifier le type d'événement
            event_type = 'unknown'
            if 'authentication failure' in line.lower():
                event_type = 'auth_failure'
            elif 'authentication success' in line.lower():
                event_type = 'auth_success'
            elif 'login' in line.lower():
                event_type = 'login'
            elif 'logout' in line.lower():
                event_type = 'logout'
            elif 'ssh' in line.lower():
                event_type = 'ssh'
            
            # Extraire l'utilisateur si possible
            user = 'unknown'
            for i, part in enumerate(parts):
                if part in ['user', 'for', 'by'] and i + 1 < len(parts):
                    user = parts[i + 1]
                    break
            
            return {
                'type': 'auth_log',
                'event_type': event_type,
                'timestamp': date_str,
                'user': user,
                'raw_line': line,
                'source': 'auth_log'
            }
        
        except Exception as e:
            logger.error(f"Error parsing auth line: {e}")
            return None
    
    def get_failed_logins(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Récupère les tentatives de connexion échouées."""
        all_logs = self.collect(hours)
        return [log for log in all_logs if log.get('event_type') == 'auth_failure']
    
    def get_successful_logins(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Récupère les connexions réussies."""
        all_logs = self.collect(hours)
        return [log for log in all_logs if log.get('event_type') == 'auth_success'] 