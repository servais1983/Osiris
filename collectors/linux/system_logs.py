"""
Collecteur pour les logs système Linux
Collecte les logs depuis /var/log/syslog, /var/log/auth.log, etc.
"""

import os
import re
from datetime import datetime
from typing import Dict, List, Any
from .base import LinuxCollector

class SystemLogsCollector(LinuxCollector):
    """Collecteur pour les logs système Linux"""
    
    def __init__(self):
        super().__init__()
        self.log_files = [
            '/var/log/syslog',
            '/var/log/auth.log',
            '/var/log/kern.log',
            '/var/log/dmesg',
            '/var/log/messages',
            '/var/log/secure'
        ]
    
    def collect(self) -> Dict[str, Any]:
        """Collecte les logs système"""
        results = {
            'system_info': self.get_system_info(),
            'log_files': {},
            'recent_events': [],
            'auth_events': [],
            'error_events': [],
            'summary': {}
        }
        
        # Collecter les logs de chaque fichier
        for log_file in self.log_files:
            if os.path.exists(log_file):
                try:
                    log_data = self._parse_log_file(log_file)
                    results['log_files'][log_file] = log_data
                    
                    # Ajouter aux événements récents
                    results['recent_events'].extend(log_data.get('recent_entries', []))
                    
                    # Filtrer les événements d'authentification
                    if 'auth' in log_file.lower():
                        results['auth_events'].extend(log_data.get('recent_entries', []))
                    
                    # Filtrer les erreurs
                    error_entries = [entry for entry in log_data.get('recent_entries', []) 
                                   if 'error' in entry.get('level', '').lower()]
                    results['error_events'].extend(error_entries)
                    
                except Exception as e:
                    self.logger.error(f"Erreur lors de la collecte du fichier {log_file}: {e}")
                    results['log_files'][log_file] = {'error': str(e)}
        
        # Collecter les logs du kernel via dmesg
        dmesg_data = self._collect_dmesg()
        results['dmesg'] = dmesg_data
        
        # Collecter les logs systemd (si disponible)
        journalctl_data = self._collect_journalctl()
        results['journalctl'] = journalctl_data
        
        # Générer un résumé
        results['summary'] = self._generate_summary(results)
        
        return results
    
    def _parse_log_file(self, log_file: str) -> Dict[str, Any]:
        """Parse un fichier de log système"""
        try:
            file_info = self.get_file_info(log_file)
            entries = []
            
            # Lire les dernières lignes du fichier
            lines = self.read_file_lines(log_file, max_lines=1000)
            
            for line in lines:
                entry = self._parse_log_line(line)
                if entry:
                    entries.append(entry)
            
            return {
                'file_info': file_info,
                'total_entries': len(entries),
                'recent_entries': entries[-100:],  # Dernières 100 entrées
                'first_entry': entries[0] if entries else None,
                'last_entry': entries[-1] if entries else None
            }
            
        except Exception as e:
            self.logger.error(f"Erreur lors du parsing du fichier {log_file}: {e}")
            return {'error': str(e)}
    
    def _parse_log_line(self, line: str) -> Dict[str, Any]:
        """Parse une ligne de log système"""
        try:
            # Pattern pour les logs syslog standard
            # Format: Jan 15 10:30:45 hostname service: message
            pattern = r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+([^:]+):\s*(.*)$'
            match = re.match(pattern, line)
            
            if match:
                timestamp_str, hostname, service, message = match.groups()
                
                # Convertir le timestamp
                try:
                    # Ajouter l'année actuelle si elle n'est pas présente
                    if len(timestamp_str.split()) == 2:
                        timestamp_str = f"{datetime.now().year} {timestamp_str}"
                    
                    timestamp = datetime.strptime(timestamp_str, "%Y %b %d %H:%M:%S")
                except:
                    timestamp = None
                
                # Détecter le niveau de log
                level = 'info'
                if any(word in message.lower() for word in ['error', 'failed', 'failure']):
                    level = 'error'
                elif any(word in message.lower() for word in ['warning', 'warn']):
                    level = 'warning'
                elif any(word in message.lower() for word in ['debug']):
                    level = 'debug'
                
                return {
                    'timestamp': timestamp.isoformat() if timestamp else None,
                    'hostname': hostname,
                    'service': service.strip(),
                    'message': message,
                    'level': level,
                    'raw_line': line
                }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Erreur lors du parsing de la ligne: {line[:100]}... - {e}")
            return None
    
    def _collect_dmesg(self) -> Dict[str, Any]:
        """Collecte les logs du kernel via dmesg"""
        try:
            result = self.execute_command(['dmesg'], timeout=10)
            
            if result['success']:
                entries = []
                lines = result['stdout'].split('\n')
                
                for line in lines:
                    if line.strip():
                        entry = self._parse_dmesg_line(line)
                        if entry:
                            entries.append(entry)
                
                return {
                    'success': True,
                    'total_entries': len(entries),
                    'recent_entries': entries[-50:],  # Dernières 50 entrées
                    'raw_output': result['stdout'][:1000]  # Premiers 1000 caractères
                }
            else:
                return {
                    'success': False,
                    'error': result.get('error', 'Unknown error')
                }
                
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte dmesg: {e}")
            return {'success': False, 'error': str(e)}
    
    def _parse_dmesg_line(self, line: str) -> Dict[str, Any]:
        """Parse une ligne de dmesg"""
        try:
            # Pattern pour dmesg: [timestamp] message
            pattern = r'^\[(\d+\.\d+)\]\s*(.*)$'
            match = re.match(pattern, line)
            
            if match:
                timestamp_float, message = match.groups()
                timestamp = float(timestamp_float)
                
                # Détecter le niveau
                level = 'info'
                if any(word in message.lower() for word in ['error', 'failed', 'failure']):
                    level = 'error'
                elif any(word in message.lower() for word in ['warning', 'warn']):
                    level = 'warning'
                
                return {
                    'timestamp': timestamp,
                    'message': message,
                    'level': level,
                    'raw_line': line
                }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Erreur lors du parsing dmesg: {line[:100]}... - {e}")
            return None
    
    def _collect_journalctl(self) -> Dict[str, Any]:
        """Collecte les logs systemd via journalctl"""
        try:
            # Vérifier si systemd est disponible
            result = self.execute_command(['which', 'journalctl'], timeout=5)
            if not result['success']:
                return {'available': False, 'reason': 'journalctl not found'}
            
            # Collecter les logs récents
            result = self.execute_command([
                'journalctl', '--no-pager', '--since', '1 hour ago', 
                '--output', 'short-precise'
            ], timeout=15)
            
            if result['success']:
                entries = []
                lines = result['stdout'].split('\n')
                
                for line in lines:
                    if line.strip():
                        entry = self._parse_journalctl_line(line)
                        if entry:
                            entries.append(entry)
                
                return {
                    'available': True,
                    'success': True,
                    'total_entries': len(entries),
                    'recent_entries': entries[-50:],
                    'raw_output': result['stdout'][:1000]
                }
            else:
                return {
                    'available': True,
                    'success': False,
                    'error': result.get('error', 'Unknown error')
                }
                
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte journalctl: {e}")
            return {'available': True, 'success': False, 'error': str(e)}
    
    def _parse_journalctl_line(self, line: str) -> Dict[str, Any]:
        """Parse une ligne de journalctl"""
        try:
            # Format: timestamp hostname service[pid]: message
            pattern = r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+(\S+)\s+([^[]+)\[(\d+)\]:\s*(.*)$'
            match = re.match(pattern, line)
            
            if match:
                timestamp_str, hostname, service, pid, message = match.groups()
                
                try:
                    timestamp = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f")
                except:
                    timestamp = None
                
                # Détecter le niveau
                level = 'info'
                if any(word in message.lower() for word in ['error', 'failed', 'failure']):
                    level = 'error'
                elif any(word in message.lower() for word in ['warning', 'warn']):
                    level = 'warning'
                
                return {
                    'timestamp': timestamp.isoformat() if timestamp else None,
                    'hostname': hostname,
                    'service': service.strip(),
                    'pid': int(pid),
                    'message': message,
                    'level': level,
                    'raw_line': line
                }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Erreur lors du parsing journalctl: {line[:100]}... - {e}")
            return None
    
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Génère un résumé des logs collectés"""
        try:
            total_entries = 0
            error_count = 0
            warning_count = 0
            auth_count = 0
            
            # Compter les entrées
            for log_file_data in results['log_files'].values():
                if 'recent_entries' in log_file_data:
                    entries = log_file_data['recent_entries']
                    total_entries += len(entries)
                    
                    for entry in entries:
                        level = entry.get('level', '').lower()
                        if 'error' in level:
                            error_count += 1
                        elif 'warning' in level:
                            warning_count += 1
                
                # Compter les événements d'authentification
                if 'auth' in log_file_data.get('file_info', {}).get('path', '').lower():
                    auth_count += len(log_file_data.get('recent_entries', []))
            
            return {
                'total_log_files': len(results['log_files']),
                'total_entries': total_entries,
                'error_count': error_count,
                'warning_count': warning_count,
                'auth_events_count': len(results['auth_events']),
                'recent_events_count': len(results['recent_events']),
                'dmesg_available': results.get('dmesg', {}).get('success', False),
                'journalctl_available': results.get('journalctl', {}).get('available', False)
            }
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la génération du résumé: {e}")
            return {'error': str(e)} 