import logging
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta
import json
import redis
from collections import defaultdict, Counter

logger = logging.getLogger(__name__)

class BaseliningService:
    def __init__(self, db_client, redis_client: redis.Redis):
        self.db = db_client
        self.redis = redis_client
        self.profile_cache = {}

    def update_user_profiles(self, hours_back: int = 24):
        """
        Analyse les événements des dernières heures et met à jour les profils.
        """
        logger.info(f"Updating user and entity behavior baselines for last {hours_back} hours")
        
        try:
            # Récupérer les événements des dernières heures
            events = self._get_recent_events(hours_back)
            
            # Analyser par utilisateur
            user_profiles = self._analyze_user_behavior(events)
            
            # Analyser par machine/hôte
            host_profiles = self._analyze_host_behavior(events)
            
            # Sauvegarder les profils
            self._save_profiles(user_profiles, host_profiles)
            
            logger.info(f"Updated {len(user_profiles)} user profiles and {len(host_profiles)} host profiles")
            
            return {
                'user_profiles_updated': len(user_profiles),
                'host_profiles_updated': len(host_profiles),
                'events_analyzed': len(events)
            }
            
        except Exception as e:
            logger.error(f"Error updating user profiles: {e}")
            return {'error': str(e)}

    def _get_recent_events(self, hours_back: int) -> List[Dict[str, Any]]:
        """Récupère les événements récents depuis la base de données."""
        try:
            # En production, cette requête serait adaptée à votre schéma de DB
            # Exemple pour PostgreSQL/ClickHouse
            cutoff_time = datetime.now() - timedelta(hours=hours_back)
            
            # Simulation de données d'événements
            mock_events = [
                {
                    'user': 'jdoe',
                    'host': 'workstation-01',
                    'type': 'process_launch',
                    'data': {'process_name': 'chrome.exe'},
                    'timestamp': (datetime.now() - timedelta(hours=2)).isoformat()
                },
                {
                    'user': 'jdoe',
                    'host': 'workstation-01',
                    'type': 'process_launch',
                    'data': {'process_name': 'code.exe'},
                    'timestamp': (datetime.now() - timedelta(hours=1)).isoformat()
                },
                {
                    'user': 'admin',
                    'host': 'server-01',
                    'type': 'process_launch',
                    'data': {'process_name': 'powershell.exe'},
                    'timestamp': (datetime.now() - timedelta(hours=3)).isoformat()
                }
            ]
            
            return mock_events
            
        except Exception as e:
            logger.error(f"Error getting recent events: {e}")
            return []

    def _analyze_user_behavior(self, events: List[Dict[str, Any]]) -> Dict[str, Dict]:
        """Analyse le comportement de chaque utilisateur."""
        user_events = defaultdict(list)
        
        # Grouper les événements par utilisateur
        for event in events:
            user = event.get('user')
            if user:
                user_events[user].append(event)
        
        user_profiles = {}
        
        for user, user_event_list in user_events.items():
            profile = self._build_user_profile(user, user_event_list)
            user_profiles[user] = profile
        
        return user_profiles

    def _build_user_profile(self, user: str, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Construit le profil d'un utilisateur spécifique."""
        profile = {
            'user_id': user,
            'last_updated': datetime.now().isoformat(),
            'normal_work_hours': self._calculate_work_hours(events),
            'frequent_hosts': self._get_frequent_hosts(events),
            'common_processes': self._get_common_processes(events),
            'rare_processes': self._get_rare_processes(events),
            'network_patterns': self._analyze_network_patterns(events),
            'file_access_patterns': self._analyze_file_access_patterns(events),
            'command_patterns': self._analyze_command_patterns(events),
            'activity_frequency': self._calculate_activity_frequency(events)
        }
        
        return profile

    def _calculate_work_hours(self, events: List[Dict[str, Any]]) -> Dict[str, str]:
        """Calcule les heures de travail habituelles."""
        hours = []
        
        for event in events:
            try:
                timestamp = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                hours.append(timestamp.hour)
            except:
                continue
        
        if hours:
            # Calculer les heures les plus fréquentes
            hour_counts = Counter(hours)
            most_common_hours = hour_counts.most_common(3)
            
            # Déterminer la plage de travail
            if most_common_hours:
                start_hour = min(hour for hour, count in most_common_hours)
                end_hour = max(hour for hour, count in most_common_hours)
                
                return {
                    'start': f"{start_hour:02d}:00",
                    'end': f"{end_hour:02d}:00",
                    'confidence': len(hours) / 100  # Confiance basée sur le nombre d'événements
                }
        
        # Valeurs par défaut
        return {'start': '09:00', 'end': '17:00', 'confidence': 0.5}

    def _get_frequent_hosts(self, events: List[Dict[str, Any]]) -> List[str]:
        """Identifie les hôtes fréquemment utilisés."""
        hosts = [event.get('host') for event in events if event.get('host')]
        host_counts = Counter(hosts)
        
        # Retourner les hôtes utilisés plus de 2 fois
        return [host for host, count in host_counts.items() if count > 2]

    def _get_common_processes(self, events: List[Dict[str, Any]]) -> List[str]:
        """Identifie les processus communs."""
        processes = []
        
        for event in events:
            if event.get('type') == 'process_launch':
                process_name = event.get('data', {}).get('process_name')
                if process_name:
                    processes.append(process_name)
        
        process_counts = Counter(processes)
        
        # Retourner les processus utilisés plus de 3 fois
        return [proc for proc, count in process_counts.items() if count > 3]

    def _get_rare_processes(self, events: List[Dict[str, Any]]) -> List[str]:
        """Identifie les processus rares (utilisés seulement 1 fois)."""
        processes = []
        
        for event in events:
            if event.get('type') == 'process_launch':
                process_name = event.get('data', {}).get('process_name')
                if process_name:
                    processes.append(process_name)
        
        process_counts = Counter(processes)
        
        # Retourner les processus utilisés seulement 1 fois
        return [proc for proc, count in process_counts.items() if count == 1]

    def _analyze_network_patterns(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyse les patterns réseau."""
        network_events = [e for e in events if e.get('type') == 'network_connection']
        
        patterns = {
            'total_connections': len(network_events),
            'unique_ips': len(set(e.get('data', {}).get('peer_address') for e in network_events if e.get('data', {}).get('peer_address'))),
            'common_ports': self._get_common_ports(network_events),
            'connection_times': self._get_connection_times(network_events)
        }
        
        return patterns

    def _get_common_ports(self, network_events: List[Dict[str, Any]]) -> List[int]:
        """Identifie les ports communs."""
        ports = []
        
        for event in network_events:
            port = event.get('data', {}).get('peer_port')
            if port:
                ports.append(port)
        
        port_counts = Counter(ports)
        return [port for port, count in port_counts.most_common(5)]

    def _get_connection_times(self, network_events: List[Dict[str, Any]]) -> Dict[str, int]:
        """Analyse les heures de connexion."""
        hours = []
        
        for event in network_events:
            try:
                timestamp = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                hours.append(timestamp.hour)
            except:
                continue
        
        if hours:
            hour_counts = Counter(hours)
            return {
                'peak_hour': hour_counts.most_common(1)[0][0] if hour_counts else 0,
                'total_connections': len(hours)
            }
        
        return {'peak_hour': 0, 'total_connections': 0}

    def _analyze_file_access_patterns(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyse les patterns d'accès aux fichiers."""
        file_events = [e for e in events if e.get('type') == 'file_access']
        
        patterns = {
            'total_accesses': len(file_events),
            'common_extensions': self._get_common_extensions(file_events),
            'sensitive_accesses': self._count_sensitive_accesses(file_events)
        }
        
        return patterns

    def _get_common_extensions(self, file_events: List[Dict[str, Any]]) -> List[str]:
        """Identifie les extensions de fichiers communes."""
        extensions = []
        
        for event in file_events:
            file_path = event.get('data', {}).get('file_path', '')
            if '.' in file_path:
                ext = file_path.split('.')[-1].lower()
                extensions.append(ext)
        
        ext_counts = Counter(extensions)
        return [ext for ext, count in ext_counts.most_common(10)]

    def _count_sensitive_accesses(self, file_events: List[Dict[str, Any]]) -> int:
        """Compte les accès aux fichiers sensibles."""
        sensitive_paths = [
            '/etc/passwd', '/etc/shadow', '/windows/system32',
            'C:\\Windows\\System32', 'C:\\Windows\\SysWOW64'
        ]
        
        count = 0
        for event in file_events:
            file_path = event.get('data', {}).get('file_path', '')
            for sensitive_path in sensitive_paths:
                if sensitive_path.lower() in file_path.lower():
                    count += 1
                    break
        
        return count

    def _analyze_command_patterns(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyse les patterns de commandes shell."""
        shell_events = [e for e in events if e.get('type') == 'shell_history']
        
        patterns = {
            'total_commands': len(shell_events),
            'common_commands': self._get_common_commands(shell_events),
            'suspicious_commands': self._count_suspicious_commands(shell_events)
        }
        
        return patterns

    def _get_common_commands(self, shell_events: List[Dict[str, Any]]) -> List[str]:
        """Identifie les commandes communes."""
        commands = []
        
        for event in shell_events:
            command = event.get('data', {}).get('command', '')
            if command:
                # Extraire la commande principale
                cmd_parts = command.split()
                if cmd_parts:
                    commands.append(cmd_parts[0])
        
        cmd_counts = Counter(commands)
        return [cmd for cmd, count in cmd_counts.most_common(10)]

    def _count_suspicious_commands(self, shell_events: List[Dict[str, Any]]) -> int:
        """Compte les commandes suspectes."""
        suspicious_commands = [
            'wget', 'curl', 'nc', 'netcat', 'nslookup', 'dig',
            'whoami', 'net user', 'net group', 'reg query',
            'powershell -enc', 'certutil -urlcache'
        ]
        
        count = 0
        for event in shell_events:
            command = event.get('data', {}).get('command', '').lower()
            for suspicious_cmd in suspicious_commands:
                if suspicious_cmd in command:
                    count += 1
                    break
        
        return count

    def _calculate_activity_frequency(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calcule la fréquence d'activité."""
        if not events:
            return {'events_per_hour': 0, 'peak_hours': []}
        
        # Grouper par heure
        hourly_counts = defaultdict(int)
        
        for event in events:
            try:
                timestamp = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                hour = timestamp.hour
                hourly_counts[hour] += 1
            except:
                continue
        
        if hourly_counts:
            avg_events_per_hour = sum(hourly_counts.values()) / len(hourly_counts)
            peak_hours = [hour for hour, count in hourly_counts.items() if count > avg_events_per_hour]
            
            return {
                'events_per_hour': round(avg_events_per_hour, 2),
                'peak_hours': sorted(peak_hours)
            }
        
        return {'events_per_hour': 0, 'peak_hours': []}

    def _analyze_host_behavior(self, events: List[Dict[str, Any]]) -> Dict[str, Dict]:
        """Analyse le comportement de chaque hôte."""
        host_events = defaultdict(list)
        
        # Grouper les événements par hôte
        for event in events:
            host = event.get('host')
            if host:
                host_events[host].append(event)
        
        host_profiles = {}
        
        for host, host_event_list in host_events.items():
            profile = self._build_host_profile(host, host_event_list)
            host_profiles[host] = profile
        
        return host_profiles

    def _build_host_profile(self, host: str, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Construit le profil d'un hôte spécifique."""
        profile = {
            'host_id': host,
            'last_updated': datetime.now().isoformat(),
            'active_users': self._get_active_users(events),
            'common_processes': self._get_common_processes(events),
            'network_activity': self._analyze_network_patterns(events),
            'file_activity': self._analyze_file_access_patterns(events),
            'uptime_patterns': self._analyze_uptime_patterns(events)
        }
        
        return profile

    def _get_active_users(self, events: List[Dict[str, Any]]) -> List[str]:
        """Identifie les utilisateurs actifs sur cet hôte."""
        users = [event.get('user') for event in events if event.get('user')]
        return list(set(users))

    def _analyze_uptime_patterns(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyse les patterns d'activité de l'hôte."""
        if not events:
            return {'active_hours': [], 'total_activity': 0}
        
        # Analyser les heures d'activité
        active_hours = set()
        
        for event in events:
            try:
                timestamp = datetime.fromisoformat(event['timestamp'].replace('Z', '+00:00'))
                active_hours.add(timestamp.hour)
            except:
                continue
        
        return {
            'active_hours': sorted(list(active_hours)),
            'total_activity': len(events)
        }

    def _save_profiles(self, user_profiles: Dict, host_profiles: Dict):
        """Sauvegarde les profils dans Redis."""
        try:
            # Sauvegarder les profils utilisateur
            for user_id, profile in user_profiles.items():
                key = f"user_profile:{user_id}"
                self.redis.set(key, json.dumps(profile), ex=24*3600)  # Expire après 24h
            
            # Sauvegarder les profils hôte
            for host_id, profile in host_profiles.items():
                key = f"host_profile:{host_id}"
                self.redis.set(key, json.dumps(profile), ex=24*3600)  # Expire après 24h
            
            # Mettre à jour le cache
            self.profile_cache.update(user_profiles)
            self.profile_cache.update(host_profiles)
            
            logger.info(f"Saved {len(user_profiles)} user profiles and {len(host_profiles)} host profiles")
            
        except Exception as e:
            logger.error(f"Error saving profiles: {e}")

    def get_user_profile(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Récupère le profil d'un utilisateur."""
        try:
            # Vérifier le cache d'abord
            if user_id in self.profile_cache:
                return self.profile_cache[user_id]
            
            # Récupérer depuis Redis
            key = f"user_profile:{user_id}"
            profile_data = self.redis.get(key)
            
            if profile_data:
                profile = json.loads(profile_data)
                self.profile_cache[user_id] = profile
                return profile
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting user profile for {user_id}: {e}")
            return None

    def get_host_profile(self, host_id: str) -> Optional[Dict[str, Any]]:
        """Récupère le profil d'un hôte."""
        try:
            key = f"host_profile:{host_id}"
            profile_data = self.redis.get(key)
            
            if profile_data:
                return json.loads(profile_data)
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting host profile for {host_id}: {e}")
            return None

    def get_profile_statistics(self) -> Dict[str, Any]:
        """Récupère les statistiques des profils."""
        try:
            user_profiles = len(self.redis.keys("user_profile:*"))
            host_profiles = len(self.redis.keys("host_profile:*"))
            
            return {
                'user_profiles_count': user_profiles,
                'host_profiles_count': host_profiles,
                'total_profiles': user_profiles + host_profiles,
                'last_update': datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting profile statistics: {e}")
            return {} 