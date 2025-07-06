import subprocess
import logging
from typing import List, Dict, Any
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class MacUnifiedLogsCollector:
    """Collecte les Unified Logs macOS."""
    
    def __init__(self):
        self.log_sources = [
            'system',
            'user',
            'signpost'
        ]
    
    def collect(self, hours_back: int = 24) -> List[Dict[str, Any]]:
        """Collecte les Unified Logs récents."""
        results = []
        
        for source in self.log_sources:
            try:
                source_results = self._collect_log_source(source, hours_back)
                results.extend(source_results)
            except Exception as e:
                logger.error(f"Error collecting {source} logs: {e}")
        
        return results
    
    def _collect_log_source(self, source: str, hours_back: int) -> List[Dict[str, Any]]:
        """Collecte les logs d'une source spécifique."""
        try:
            cmd = [
                'log', 'show',
                '--predicate', 'eventType == logEvent',
                '--style', 'json',
                '--last', f'{hours_back}h'
            ]
            
            if source == 'user':
                cmd.extend(['--user', 'current'])
            elif source == 'system':
                cmd.extend(['--system'])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode != 0:
                logger.error(f"log command failed: {result.stderr}")
                return []
            
            # Parser la sortie JSON
            import json
            try:
                log_entries = json.loads(result.stdout)
                return self._parse_log_entries(log_entries, source)
            except json.JSONDecodeError:
                logger.error("Failed to parse log output as JSON")
                return []
        
        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout collecting {source} logs")
            return []
        except Exception as e:
            logger.error(f"Error collecting {source} logs: {e}")
            return []
    
    def _parse_log_entries(self, log_entries: List[Dict], source: str) -> List[Dict[str, Any]]:
        """Parse les entrées de log."""
        results = []
        
        for entry in log_entries:
            try:
                parsed = self._parse_log_entry(entry, source)
                if parsed:
                    results.append(parsed)
            except Exception as e:
                logger.error(f"Error parsing log entry: {e}")
        
        return results
    
    def _parse_log_entry(self, entry: Dict, source: str) -> Dict[str, Any]:
        """Parse une entrée de log individuelle."""
        try:
            # Extraire les informations de base
            timestamp = entry.get('timestamp', '')
            subsystem = entry.get('subsystem', '')
            category = entry.get('category', '')
            message = entry.get('message', '')
            
            # Déterminer le type d'événement
            event_type = self._determine_event_type(subsystem, category, message)
            
            return {
                'type': 'macos_unified_log',
                'source': source,
                'timestamp': timestamp,
                'subsystem': subsystem,
                'category': category,
                'message': message,
                'event_type': event_type,
                'severity': entry.get('level', 'info'),
                'process': entry.get('process', ''),
                'thread': entry.get('thread', '')
            }
        
        except Exception as e:
            logger.error(f"Error parsing log entry: {e}")
            return None
    
    def _determine_event_type(self, subsystem: str, category: str, message: str) -> str:
        """Détermine le type d'événement basé sur le contenu."""
        message_lower = message.lower()
        subsystem_lower = subsystem.lower()
        
        # Événements d'authentification
        if any(keyword in message_lower for keyword in ['login', 'logout', 'authentication']):
            return 'authentication'
        
        # Événements de processus
        if any(keyword in message_lower for keyword in ['process', 'launch', 'terminate']):
            return 'process'
        
        # Événements réseau
        if any(keyword in message_lower for keyword in ['network', 'connection', 'socket']):
            return 'network'
        
        # Événements de fichiers
        if any(keyword in message_lower for keyword in ['file', 'access', 'permission']):
            return 'file_access'
        
        # Événements de sécurité
        if any(keyword in message_lower for keyword in ['security', 'quarantine', 'malware']):
            return 'security'
        
        # Événements système
        if subsystem_lower in ['com.apple.xpc', 'com.apple.system']:
            return 'system'
        
        return 'general'
    
    def get_security_events(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Récupère les événements de sécurité."""
        all_logs = self.collect(hours)
        return [log for log in all_logs if log.get('event_type') == 'security']
    
    def get_authentication_events(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Récupère les événements d'authentification."""
        all_logs = self.collect(hours)
        return [log for log in all_logs if log.get('event_type') == 'authentication']
    
    def get_process_events(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Récupère les événements de processus."""
        all_logs = self.collect(hours)
        return [log for log in all_logs if log.get('event_type') == 'process']
    
    def search_logs(self, predicate: str, hours: int = 24) -> List[Dict[str, Any]]:
        """Recherche dans les logs avec un prédicat personnalisé."""
        try:
            cmd = [
                'log', 'show',
                '--predicate', predicate,
                '--style', 'json',
                '--last', f'{hours}h'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode != 0:
                logger.error(f"log search failed: {result.stderr}")
                return []
            
            import json
            try:
                log_entries = json.loads(result.stdout)
                return self._parse_log_entries(log_entries, 'search')
            except json.JSONDecodeError:
                logger.error("Failed to parse search results as JSON")
                return []
        
        except subprocess.TimeoutExpired:
            logger.warning("Timeout searching logs")
            return []
        except Exception as e:
            logger.error(f"Error searching logs: {e}")
            return [] 