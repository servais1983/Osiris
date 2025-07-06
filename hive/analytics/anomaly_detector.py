import logging
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
import json

logger = logging.getLogger(__name__)

class AnomalyDetector:
    def __init__(self, profile_db, redis_client):
        self.profiles = profile_db
        self.redis = redis_client
        self.anomaly_thresholds = {
            'process_launch': 20,
            'network_connection': 15,
            'file_access': 10,
            'shell_history': 25,
            'off_hours': 30,
            'weekend': 25,
            'suspicious_command': 40,
            'suspicious_process': 35
        }

    def score_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Attribue un score d'anomalie à un événement.
        """
        anomaly_score = 0
        anomaly_reasons = []
        
        try:
            # Récupérer le profil de l'utilisateur
            user = event.get('user')
            user_profile = None
            if user:
                user_profile = self.profiles.get_user_profile(user)
            
            # Récupérer le profil de l'hôte
            host = event.get('host')
            host_profile = None
            if host:
                host_profile = self.profiles.get_host_profile(host)
            
            # Analyser selon le type d'événement
            event_type = event.get('type')
            
            if event_type == 'process_launch':
                score, reasons = self._score_process_launch(event, user_profile, host_profile)
                anomaly_score += score
                anomaly_reasons.extend(reasons)
            
            elif event_type == 'network_connection':
                score, reasons = self._score_network_connection(event, user_profile, host_profile)
                anomaly_score += score
                anomaly_reasons.extend(reasons)
            
            elif event_type == 'file_access':
                score, reasons = self._score_file_access(event, user_profile, host_profile)
                anomaly_score += score
                anomaly_reasons.extend(reasons)
            
            elif event_type == 'shell_history':
                score, reasons = self._score_shell_history(event, user_profile, host_profile)
                anomaly_score += score
                anomaly_reasons.extend(reasons)
            
            # Analyser les aspects temporels
            temporal_score, temporal_reasons = self._score_temporal_aspects(event, user_profile)
            anomaly_score += temporal_score
            anomaly_reasons.extend(temporal_reasons)
            
            # Analyser les aspects contextuels
            context_score, context_reasons = self._score_contextual_aspects(event)
            anomaly_score += context_score
            anomaly_reasons.extend(context_reasons)
            
            # Ajouter le score d'anomalie à l'événement
            event['anomaly_score'] = anomaly_score
            event['anomaly_reasons'] = anomaly_reasons
            
            # Déterminer la criticité basée sur le score
            event['criticality'] = self._determine_criticality(anomaly_score)
            
            # Ajouter des tags si anomalie détectée
            if anomaly_score > 0:
                event['tags'] = event.get('tags', []) + ['anomaly_detected']
            
            logger.debug(f"Event scored: {anomaly_score} points, reasons: {anomaly_reasons}")
            
        except Exception as e:
            logger.error(f"Error scoring event: {e}")
            event['anomaly_score'] = 0
            event['anomaly_reasons'] = ['Error during scoring']
        
        return event

    def _score_process_launch(self, event: Dict[str, Any], user_profile: Optional[Dict], host_profile: Optional[Dict]) -> tuple[int, list[str]]:
        """Score un événement de lancement de processus."""
        score = 0
        reasons = []
        
        data = event.get('data', {})
        process_name = data.get('process_name', '')
        
        if not process_name:
            return score, reasons
        
        # Vérifier contre le profil utilisateur
        if user_profile:
            common_processes = user_profile.get('common_processes', [])
            rare_processes = user_profile.get('rare_processes', [])
            
            if process_name in rare_processes:
                score += self.anomaly_thresholds['process_launch']
                reasons.append(f"Rare process for user: {process_name}")
            elif process_name not in common_processes:
                score += self.anomaly_thresholds['process_launch'] // 2
                reasons.append(f"Uncommon process for user: {process_name}")
        
        # Vérifier contre le profil hôte
        if host_profile:
            host_common_processes = host_profile.get('common_processes', [])
            
            if process_name not in host_common_processes:
                score += 5
                reasons.append(f"Uncommon process for host: {process_name}")
        
        # Vérifier les processus suspects
        suspicious_processes = [
            'cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe',
            'regsvr32.exe', 'rundll32.exe', 'mshta.exe', 'certutil.exe',
            'regedit.exe', 'diskpart.exe', 'net.exe', 'netstat.exe'
        ]
        
        if process_name.lower() in suspicious_processes:
            score += self.anomaly_thresholds['suspicious_process']
            reasons.append(f"Suspicious process: {process_name}")
        
        return score, reasons

    def _score_network_connection(self, event: Dict[str, Any], user_profile: Optional[Dict], host_profile: Optional[Dict]) -> tuple[int, list[str]]:
        """Score un événement de connexion réseau."""
        score = 0
        reasons = []
        
        data = event.get('data', {})
        peer_ip = data.get('peer_address')
        peer_port = data.get('peer_port')
        
        if not peer_ip:
            return score, reasons
        
        # Vérifier contre le profil utilisateur
        if user_profile:
            network_patterns = user_profile.get('network_patterns', {})
            common_ports = network_patterns.get('common_ports', [])
            
            if peer_port and peer_port not in common_ports:
                score += 10
                reasons.append(f"Uncommon port for user: {peer_port}")
        
        # Vérifier contre le profil hôte
        if host_profile:
            host_network_patterns = host_profile.get('network_activity', {})
            host_common_ports = host_network_patterns.get('common_ports', [])
            
            if peer_port and peer_port not in host_common_ports:
                score += 5
                reasons.append(f"Uncommon port for host: {peer_port}")
        
        # Vérifier les ports suspects
        suspicious_ports = [22, 23, 3389, 5900, 8080, 4444, 1337]
        if peer_port in suspicious_ports:
            score += 15
            reasons.append(f"Suspicious port: {peer_port}")
        
        # Vérifier les IP suspectes (déjà fait par l'enrichissement Threat Intel)
        if event.get('threat_intel'):
            score += 50
            reasons.append("IP found in threat intelligence feeds")
        
        return score, reasons

    def _score_file_access(self, event: Dict[str, Any], user_profile: Optional[Dict], host_profile: Optional[Dict]) -> tuple[int, list[str]]:
        """Score un événement d'accès aux fichiers."""
        score = 0
        reasons = []
        
        data = event.get('data', {})
        file_path = data.get('file_path', '')
        
        if not file_path:
            return score, reasons
        
        # Vérifier les accès aux fichiers sensibles
        sensitive_paths = [
            '/etc/passwd', '/etc/shadow', '/windows/system32',
            'C:\\Windows\\System32', 'C:\\Windows\\SysWOW64',
            '/etc/ssh/', '/root/', 'C:\\Windows\\Temp'
        ]
        
        for sensitive_path in sensitive_paths:
            if sensitive_path.lower() in file_path.lower():
                score += self.anomaly_thresholds['file_access']
                reasons.append(f"Access to sensitive path: {sensitive_path}")
                break
        
        # Vérifier les extensions suspectes
        suspicious_extensions = ['.exe', '.dll', '.bat', '.ps1', '.vbs', '.js', '.jar']
        file_extension = file_path.lower().split('.')[-1] if '.' in file_path else ''
        
        if file_extension in suspicious_extensions:
            score += 10
            reasons.append(f"Access to suspicious file type: .{file_extension}")
        
        return score, reasons

    def _score_shell_history(self, event: Dict[str, Any], user_profile: Optional[Dict], host_profile: Optional[Dict]) -> tuple[int, list[str]]:
        """Score un événement d'historique shell."""
        score = 0
        reasons = []
        
        data = event.get('data', {})
        command = data.get('command', '')
        
        if not command:
            return score, reasons
        
        # Vérifier contre le profil utilisateur
        if user_profile:
            command_patterns = user_profile.get('command_patterns', {})
            common_commands = command_patterns.get('common_commands', [])
            
            # Extraire la commande principale
            cmd_parts = command.split()
            if cmd_parts and cmd_parts[0] not in common_commands:
                score += 10
                reasons.append(f"Uncommon command for user: {cmd_parts[0]}")
        
        # Vérifier les commandes suspectes
        suspicious_commands = [
            'wget', 'curl', 'nc', 'netcat', 'nslookup', 'dig',
            'whoami', 'net user', 'net group', 'reg query',
            'powershell -enc', 'certutil -urlcache', 'bitsadmin',
            'schtasks', 'at', 'sc', 'net start', 'net stop'
        ]
        
        command_lower = command.lower()
        for suspicious_cmd in suspicious_commands:
            if suspicious_cmd in command_lower:
                score += self.anomaly_thresholds['suspicious_command']
                reasons.append(f"Suspicious command: {suspicious_cmd}")
                break
        
        # Vérifier les tentatives de téléchargement
        download_indicators = ['http://', 'https://', 'ftp://', 'tftp://']
        for indicator in download_indicators:
            if indicator in command:
                score += 20
                reasons.append(f"Download attempt detected")
                break
        
        # Vérifier les tentatives de reconnaissance
        recon_commands = ['whoami', 'hostname', 'ipconfig', 'ifconfig', 'netstat', 'net view']
        for recon_cmd in recon_commands:
            if recon_cmd in command_lower:
                score += 15
                reasons.append(f"Reconnaissance command: {recon_cmd}")
                break
        
        return score, reasons

    def _score_temporal_aspects(self, event: Dict[str, Any], user_profile: Optional[Dict]) -> tuple[int, list[str]]:
        """Score les aspects temporels d'un événement."""
        score = 0
        reasons = []
        
        timestamp = event.get('timestamp')
        if not timestamp:
            return score, reasons
        
        try:
            dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            hour = dt.hour
            weekday = dt.weekday()
            
            # Vérifier les heures hors travail
            if user_profile:
                work_hours = user_profile.get('normal_work_hours', {})
                start_hour = int(work_hours.get('start', '09:00').split(':')[0])
                end_hour = int(work_hours.get('end', '17:00').split(':')[0])
                
                if hour < start_hour or hour > end_hour:
                    score += self.anomaly_thresholds['off_hours']
                    reasons.append(f"Activity outside work hours: {hour:02d}:00")
            
            # Vérifier l'activité en weekend
            if weekday >= 5:  # Samedi ou dimanche
                score += self.anomaly_thresholds['weekend']
                reasons.append(f"Weekend activity detected")
            
        except Exception as e:
            logger.error(f"Error analyzing temporal aspects: {e}")
        
        return score, reasons

    def _score_contextual_aspects(self, event: Dict[str, Any]) -> tuple[int, list[str]]:
        """Score les aspects contextuels d'un événement."""
        score = 0
        reasons = []
        
        # Vérifier si l'événement a déjà été marqué comme suspect
        if event.get('suspicious_process'):
            score += 10
            reasons.append("Process marked as suspicious")
        
        if event.get('suspicious_command'):
            score += 15
            reasons.append("Command marked as suspicious")
        
        if event.get('suspicious_file'):
            score += 10
            reasons.append("File access marked as suspicious")
        
        if event.get('off_hours'):
            score += 5
            reasons.append("Activity during off hours")
        
        if event.get('weekend'):
            score += 5
            reasons.append("Weekend activity")
        
        # Vérifier les tags existants
        tags = event.get('tags', [])
        if 'threat_intel_match' in tags:
            score += 30
            reasons.append("Threat intelligence match")
        
        if 'suspicious_process' in tags:
            score += 20
            reasons.append("Suspicious process tag")
        
        return score, reasons

    def _determine_criticality(self, anomaly_score: int) -> str:
        """Détermine la criticité basée sur le score d'anomalie."""
        if anomaly_score >= 80:
            return 'critical'
        elif anomaly_score >= 50:
            return 'high'
        elif anomaly_score >= 25:
            return 'medium'
        elif anomaly_score >= 10:
            return 'low'
        else:
            return 'info'

    def get_anomaly_statistics(self) -> Dict[str, Any]:
        """Récupère les statistiques de détection d'anomalies."""
        try:
            # En production, ces statistiques seraient stockées dans Redis ou une DB
            stats = {
                'total_events_scored': 0,
                'anomalies_detected': 0,
                'average_score': 0,
                'critical_anomalies': 0,
                'high_anomalies': 0,
                'medium_anomalies': 0,
                'low_anomalies': 0
            }
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting anomaly statistics: {e}")
            return {}

    def update_thresholds(self, new_thresholds: Dict[str, int]):
        """Met à jour les seuils d'anomalie."""
        self.anomaly_thresholds.update(new_thresholds)
        logger.info(f"Updated anomaly thresholds: {new_thresholds}")

    def get_current_thresholds(self) -> Dict[str, int]:
        """Récupère les seuils actuels."""
        return self.anomaly_thresholds.copy() 