import json
import logging
from typing import Dict, Any, Optional
import redis

logger = logging.getLogger(__name__)

class EnrichmentService:
    def __init__(self, redis_client: redis.Redis):
        self.redis_client = redis_client

    def enrich_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrichit un événement avec des renseignements contextuels.
        """
        try:
            # Enrichissement Threat Intel pour les connexions réseau
            if event.get('type') == 'network_connection':
                event = self._enrich_network_connection(event)
            
            # Enrichissement pour les lancements de processus
            elif event.get('type') == 'process_launch':
                event = self._enrich_process_launch(event)
            
            # Enrichissement pour les accès aux fichiers
            elif event.get('type') == 'file_access':
                event = self._enrich_file_access(event)
            
            # Enrichissement pour les connexions shell
            elif event.get('type') == 'shell_history':
                event = self._enrich_shell_history(event)
            
            # Enrichissement géographique pour les IP
            event = self._enrich_geographic_info(event)
            
            # Enrichissement temporel
            event = self._enrich_temporal_info(event)
            
            return event
            
        except Exception as e:
            logger.error(f"Error enriching event: {e}")
            return event

    def _enrich_network_connection(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enrichit un événement de connexion réseau."""
        data = event.get('data', {})
        peer_ip = data.get('peer_address')
        
        if not peer_ip:
            return event
        
        # Vérifier si l'IP est dans notre base de renseignements
        threat_info = self.redis_client.get(f"threat_intel:ip:{peer_ip}")
        if threat_info:
            try:
                threat_data = json.loads(threat_info)
                logger.warning(f"THREAT INTEL MATCH: IP {peer_ip} found in intelligence feeds.")
                
                event['threat_intel'] = threat_data
                event['criticality'] = 'high'
                event['tags'] = event.get('tags', []) + ['threat_intel_match', 'malicious_ip']
                
                # Ajouter des détails supplémentaires
                event['threat_details'] = {
                    'source': threat_data.get('source'),
                    'type': threat_data.get('type'),
                    'confidence': 'high'
                }
                
            except json.JSONDecodeError:
                logger.error(f"Invalid JSON in threat intel data for IP {peer_ip}")
        
        return event

    def _enrich_process_launch(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enrichit un événement de lancement de processus."""
        data = event.get('data', {})
        process_name = data.get('process_name', '')
        
        if not process_name:
            return event
        
        # Vérifier les processus suspects connus
        suspicious_processes = [
            'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
            'regsvr32.exe', 'rundll32.exe', 'mshta.exe', 'certutil.exe'
        ]
        
        if process_name.lower() in suspicious_processes:
            event['suspicious_process'] = True
            event['tags'] = event.get('tags', []) + ['suspicious_process']
            
            # Augmenter la criticité si c'est un processus très suspect
            if process_name.lower() in ['mshta.exe', 'regsvr32.exe']:
                event['criticality'] = 'medium'
        
        return event

    def _enrich_file_access(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enrichit un événement d'accès aux fichiers."""
        data = event.get('data', {})
        file_path = data.get('file_path', '')
        
        if not file_path:
            return event
        
        # Vérifier les extensions suspectes
        suspicious_extensions = ['.exe', '.dll', '.bat', '.ps1', '.vbs', '.js']
        file_extension = file_path.lower().split('.')[-1] if '.' in file_path else ''
        
        if file_extension in suspicious_extensions:
            event['suspicious_file'] = True
            event['tags'] = event.get('tags', []) + ['suspicious_file']
        
        # Vérifier les emplacements sensibles
        sensitive_paths = [
            '/etc/passwd', '/etc/shadow', '/windows/system32',
            'C:\\Windows\\System32', 'C:\\Windows\\SysWOW64'
        ]
        
        for sensitive_path in sensitive_paths:
            if sensitive_path.lower() in file_path.lower():
                event['sensitive_file_access'] = True
                event['tags'] = event.get('tags', []) + ['sensitive_file_access']
                event['criticality'] = 'medium'
                break
        
        return event

    def _enrich_shell_history(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enrichit un événement d'historique shell."""
        data = event.get('data', {})
        command = data.get('command', '')
        
        if not command:
            return event
        
        # Vérifier les commandes suspectes
        suspicious_commands = [
            'wget', 'curl', 'nc', 'netcat', 'nslookup', 'dig',
            'whoami', 'net user', 'net group', 'reg query',
            'powershell -enc', 'certutil -urlcache'
        ]
        
        command_lower = command.lower()
        for suspicious_cmd in suspicious_commands:
            if suspicious_cmd in command_lower:
                event['suspicious_command'] = True
                event['tags'] = event.get('tags', []) + ['suspicious_command']
                event['criticality'] = 'medium'
                break
        
        # Vérifier les tentatives de téléchargement
        download_indicators = ['http://', 'https://', 'ftp://']
        for indicator in download_indicators:
            if indicator in command:
                event['download_attempt'] = True
                event['tags'] = event.get('tags', []) + ['download_attempt']
                break
        
        return event

    def _enrich_geographic_info(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enrichit avec des informations géographiques."""
        data = event.get('data', {})
        peer_ip = data.get('peer_address')
        
        if not peer_ip:
            return event
        
        # Vérifier si on a déjà des infos géographiques
        if 'geo_country' not in data or data['geo_country'] == 'Unknown':
            # Simuler une géolocalisation (en production, utiliser une vraie API)
            geo_info = self._get_geo_info(peer_ip)
            if geo_info:
                data['geo_country'] = geo_info.get('country', 'Unknown')
                data['geo_city'] = geo_info.get('city', 'Unknown')
                data['geo_isp'] = geo_info.get('isp', 'Unknown')
        
        return event

    def _get_geo_info(self, ip: str) -> Optional[Dict[str, str]]:
        """Récupère les informations géographiques d'une IP."""
        # En production, utiliser une vraie API comme MaxMind GeoIP2
        # Pour l'instant, simulation basique
        try:
            # Simulation basée sur les plages d'IP
            if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
                return {'country': 'Local', 'city': 'Internal', 'isp': 'Internal'}
            elif ip.startswith('8.8.8.') or ip.startswith('8.8.4.'):
                return {'country': 'US', 'city': 'Mountain View', 'isp': 'Google'}
            else:
                return {'country': 'Unknown', 'city': 'Unknown', 'isp': 'Unknown'}
        except:
            return None

    def _enrich_temporal_info(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Enrichit avec des informations temporelles."""
        from datetime import datetime
        
        timestamp = event.get('timestamp')
        if not timestamp:
            return event
        
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            
            # Heure de la journée
            hour = dt.hour
            if 22 <= hour or hour <= 6:
                event['off_hours'] = True
                event['tags'] = event.get('tags', []) + ['off_hours']
                event['criticality'] = event.get('criticality', 'low')
            
            # Jour de la semaine
            weekday = dt.weekday()
            if weekday >= 5:  # Samedi ou dimanche
                event['weekend'] = True
                event['tags'] = event.get('tags', []) + ['weekend']
                event['criticality'] = event.get('criticality', 'low')
            
            # Ajouter l'heure locale
            event['local_time'] = dt.strftime('%H:%M:%S')
            event['day_of_week'] = dt.strftime('%A')
            
        except Exception as e:
            logger.error(f"Error enriching temporal info: {e}")
        
        return event

    def enrich_batch(self, events: list[Dict[str, Any]]) -> list[Dict[str, Any]]:
        """
        Enrichit un lot d'événements.
        """
        enriched_events = []
        
        for event in events:
            try:
                enriched_event = self.enrich_event(event)
                enriched_events.append(enriched_event)
            except Exception as e:
                logger.error(f"Error enriching event in batch: {e}")
                enriched_events.append(event)  # Garder l'événement original
        
        return enriched_events

    def get_enrichment_statistics(self) -> Dict[str, any]:
        """Récupère les statistiques d'enrichissement."""
        try:
            # Compter les événements enrichis par type
            stats = {
                'threat_intel_matches': 0,
                'suspicious_processes': 0,
                'suspicious_files': 0,
                'suspicious_commands': 0,
                'off_hours_events': 0,
                'weekend_events': 0
            }
            
            # En production, ces statistiques seraient stockées dans Redis ou une DB
            # Pour l'instant, on retourne des valeurs simulées
            return stats
            
        except Exception as e:
            logger.error(f"Error getting enrichment statistics: {e}")
            return {}

    def add_custom_enrichment_rule(self, rule_name: str, rule_config: Dict[str, Any]) -> bool:
        """
        Ajoute une règle d'enrichissement personnalisée.
        """
        try:
            # Stocker la règle dans Redis
            key = f"enrichment_rule:{rule_name}"
            self.redis_client.set(key, json.dumps(rule_config))
            
            logger.info(f"Added custom enrichment rule: {rule_name}")
            return True
            
        except Exception as e:
            logger.error(f"Error adding custom enrichment rule: {e}")
            return False

    def get_custom_enrichment_rules(self) -> Dict[str, any]:
        """
        Récupère toutes les règles d'enrichissement personnalisées.
        """
        try:
            rules = {}
            pattern = "enrichment_rule:*"
            
            for key in self.redis_client.scan_iter(match=pattern):
                rule_name = key.decode('utf-8').split(':', 1)[1]
                rule_data = self.redis_client.get(key)
                
                if rule_data:
                    rules[rule_name] = json.loads(rule_data)
            
            return rules
            
        except Exception as e:
            logger.error(f"Error getting custom enrichment rules: {e}")
            return {} 