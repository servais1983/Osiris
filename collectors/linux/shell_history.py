"""
Collecteur pour l'historique des shells Linux
Collecte .bash_history, .zsh_history, etc. avec support des timestamps
"""

import os
import re
import pwd
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Iterator
from .base import LinuxCollector

class ShellHistoryCollector(LinuxCollector):
    """Collecteur pour l'historique des shells Linux"""
    
    def __init__(self):
        super().__init__()
        # Fichiers d'historique supportés
        self.history_files = {
            '.bash_history': self._parse_bash_history,
            '.zsh_history': self._parse_zsh_history,
            '.fish_history': self._parse_fish_history,
            '.tcsh_history': self._parse_tcsh_history,
            '.ksh_history': self._parse_ksh_history
        }
    
    def _geteuid(self):
        # Méthode utilitaire multi-OS
        try:
            return os.geteuid()
        except AttributeError:
            return 0  # Par défaut, root sur Windows ou OS sans geteuid
    
    def collect(self) -> Dict[str, Any]:
        """Collecte l'historique des shells"""
        results = {
            'system_info': self.get_system_info(),
            'history_entries': [],
            'users_analyzed': [],
            'suspicious_commands': [],
            'summary': {}
        }
        
        try:
            # Collecter l'historique de tous les utilisateurs
            all_history = self._collect_all_users_history()
            results['history_entries'] = all_history
            
            # Analyser les commandes suspectes
            results['suspicious_commands'] = self._analyze_suspicious_commands(all_history)
            
            # Générer un résumé
            results['summary'] = self._generate_summary(results)
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte de l'historique: {e}")
        
        return results
    
    def _collect_all_users_history(self) -> List[Dict[str, Any]]:
        """Collecte l'historique de tous les utilisateurs"""
        all_history = []
        
        try:
            # Obtenir la liste des utilisateurs
            users = self._get_users_list()
            
            for user in users:
                try:
                    user_history = self._collect_user_history(user)
                    if user_history:
                        all_history.extend(user_history)
                        results['users_analyzed'].append(user['username'])
                except Exception as e:
                    self.logger.error(f"Erreur lors de la collecte de l'historique pour {user['username']}: {e}")
        
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte de l'historique: {e}")
        
        return all_history
    
    def _get_users_list(self) -> List[Dict[str, Any]]:
        """Obtient la liste des utilisateurs du système"""
        users = []
        
        try:
            # Utiliser la méthode de la classe de base qui gère pwd
            if hasattr(self, 'get_users_list'):
                users = self.get_users_list()
            else:
                # Fallback si la méthode n'existe pas
                try:
                    import pwd
                    for user_entry in pwd.getpwall():
                        users.append({
                            'username': user_entry.pw_name,
                            'uid': user_entry.pw_uid,
                            'home': user_entry.pw_dir
                        })
                except ImportError:
                    self.logger.warning("Module pwd non disponible sur ce système.")
                    return []
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des utilisateurs: {e}")
        
        return users
    
    def _collect_user_history(self, username: str, home_dir: str) -> List[Dict[str, Any]]:
        """Collecte l'historique d'un utilisateur spécifique"""
        user_entries = []
        
        for filename, parser_func in self.history_files.items():
            file_path = os.path.join(home_dir, filename)
            
            if os.path.exists(file_path):
                try:
                    entries = parser_func(file_path, username)
                    user_entries.extend(entries)
                except Exception as e:
                    self.logger.error(f"Erreur lors de la lecture de {file_path}: {e}")
        
        return user_entries
    
    def _parse_bash_history(self, file_path: str, username: str) -> List[Dict[str, Any]]:
        """Parse l'historique bash avec support des timestamps"""
        entries = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            i = 0
            while i < len(lines):
                line = lines[i].strip()
                
                # Vérifier si c'est un timestamp bash (format: #1234567890)
                timestamp = None
                command = line
                
                if line.startswith('#') and line[1:].isdigit():
                    try:
                        timestamp = datetime.fromtimestamp(int(line[1:]))
                        # La commande suivante correspond à ce timestamp
                        if i + 1 < len(lines):
                            command = lines[i + 1].strip()
                            i += 1
                    except ValueError:
                        pass
                
                if command and not command.startswith('#'):
                    entries.append({
                        'username': username,
                        'command': command,
                        'timestamp': timestamp.isoformat() if timestamp else None,
                        'shell_type': 'bash',
                        'file_path': file_path,
                        'line_number': i + 1
                    })
                
                i += 1
        
        except Exception as e:
            self.logger.error(f"Erreur lors du parsing bash de {file_path}: {e}")
        
        return entries
    
    def _parse_zsh_history(self, file_path: str, username: str) -> List[Dict[str, Any]]:
        """Parse l'historique zsh avec timestamps"""
        entries = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Format zsh: : timestamp:0;command
                    match = re.match(r'^: (\d+):(\d+);(.+)$', line)
                    if match:
                        timestamp_sec, timestamp_usec, command = match.groups()
                        try:
                            timestamp = datetime.fromtimestamp(
                                int(timestamp_sec) + int(timestamp_usec) / 1000000
                            )
                        except ValueError:
                            timestamp = None
                        
                        entries.append({
                            'username': username,
                            'command': command,
                            'timestamp': timestamp.isoformat() if timestamp else None,
                            'shell_type': 'zsh',
                            'file_path': file_path,
                            'line_number': line_num
                        })
                    else:
                        # Format simple sans timestamp
                        entries.append({
                            'username': username,
                            'command': line,
                            'timestamp': None,
                            'shell_type': 'zsh',
                            'file_path': file_path,
                            'line_number': line_num
                        })
        
        except Exception as e:
            self.logger.error(f"Erreur lors du parsing zsh de {file_path}: {e}")
        
        return entries
    
    def _parse_fish_history(self, file_path: str, username: str) -> List[Dict[str, Any]]:
        """Parse l'historique fish"""
        entries = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Format fish: - cmd: command
                    match = re.match(r'^- cmd: (.+)$', line)
                    if match:
                        command = match.group(1)
                        entries.append({
                            'username': username,
                            'command': command,
                            'timestamp': None,  # Fish ne stocke pas les timestamps par défaut
                            'shell_type': 'fish',
                            'file_path': file_path,
                            'line_number': line_num
                        })
        
        except Exception as e:
            self.logger.error(f"Erreur lors du parsing fish de {file_path}: {e}")
        
        return entries
    
    def _parse_tcsh_history(self, file_path: str, username: str) -> List[Dict[str, Any]]:
        """Parse l'historique tcsh"""
        entries = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        entries.append({
                            'username': username,
                            'command': line,
                            'timestamp': None,
                            'shell_type': 'tcsh',
                            'file_path': file_path,
                            'line_number': line_num
                        })
        
        except Exception as e:
            self.logger.error(f"Erreur lors du parsing tcsh de {file_path}: {e}")
        
        return entries
    
    def _parse_ksh_history(self, file_path: str, username: str) -> List[Dict[str, Any]]:
        """Parse l'historique ksh"""
        entries = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if line and not line.startswith('#'):
                        entries.append({
                            'username': username,
                            'command': line,
                            'timestamp': None,
                            'shell_type': 'ksh',
                            'file_path': file_path,
                            'line_number': line_num
                        })
        
        except Exception as e:
            self.logger.error(f"Erreur lors du parsing ksh de {file_path}: {e}")
        
        return entries
    
    def _analyze_suspicious_commands(self, entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyse les commandes suspectes"""
        suspicious_commands = []
        
        # Patterns de commandes suspectes
        suspicious_patterns = [
            r'\b(wget|curl)\s+.*\b(http|https)://',
            r'\b(nc|netcat|ncat)\s+.*\b(connect|listen)',
            r'\b(ssh|scp)\s+.*\b(root@|admin@)',
            r'\b(telnet|rsh|rlogin)\b',
            r'\b(sudo|su)\s+.*\b(root|admin)',
            r'\b(chmod|chown)\s+.*\b777|666',
            r'\b(rm|del)\s+.*\b(-rf|/rf)',
            r'\b(passwd|password)\s+.*\b(root|admin)',
            r'\b(service|systemctl)\s+.*\b(stop|disable)',
            r'\b(ufw|iptables)\s+.*\b(disable|stop)',
            r'\b(crontab|at)\s+.*\b(-e|-r)',
            r'\b(ssh-keygen|ssh-copy-id)',
            r'\b(base64|openssl)\s+.*\b(decode|decrypt)',
            r'\b(python|perl|ruby)\s+.*\b(-c|-e)',
            r'\b(eval|exec)\s+.*\b(\$|`)',
            r'\b(echo|printf)\s+.*\b(\$|`)',
            r'\b(backdoor|trojan|malware|virus)\b',
            r'\b(keylogger|logger|spy)\b',
            r'\b(exploit|payload|shell)\b',
            r'\b(miner|mining)\b'
        ]
        
        # Compiler les patterns
        compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in suspicious_patterns]
        
        for entry in entries:
            command = entry.get('command', '')
            suspicious_flags = []
            
            # Vérifier les patterns suspects
            for i, pattern in enumerate(compiled_patterns):
                if pattern.search(command):
                    suspicious_flags.append(f"Pattern suspect {i+1}: {suspicious_patterns[i]}")
            
            # Vérifier les commandes exécutées par root
            if entry.get('username') == 'root':
                suspicious_flags.append("Commande exécutée par root")
            
            # Vérifier les commandes avec des chemins suspects
            if any(path in command for path in ['/tmp/', '/var/tmp/', '/dev/shm/']):
                suspicious_flags.append("Utilisation de répertoires temporaires")
            
            # Vérifier les redirections suspectes
            if '>/dev/null' in command or '2>/dev/null' in command:
                suspicious_flags.append("Redirection vers /dev/null")
            
            # Si des flags suspects sont trouvés
            if suspicious_flags:
                suspicious_commands.append({
                    'entry': entry,
                    'suspicious_flags': suspicious_flags,
                    'risk_level': self._assess_command_risk(suspicious_flags)
                })
        
        return suspicious_commands
    
    def _assess_command_risk(self, flags: List[str]) -> str:
        """Évalue le niveau de risque d'une commande"""
        high_risk_flags = [
            "Pattern suspect",
            "Commande exécutée par root",
            "Utilisation de répertoires temporaires"
        ]
        
        medium_risk_flags = [
            "Redirection vers /dev/null"
        ]
        
        if any(any(high_flag in flag for high_flag in high_risk_flags) for flag in flags):
            return 'high'
        elif any(any(medium_flag in flag for medium_flag in medium_risk_flags) for flag in flags):
            return 'medium'
        else:
            return 'low'
    
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Génère un résumé de l'historique des shells"""
        try:
            entries = results.get('history_entries', [])
            users_analyzed = results.get('users_analyzed', [])
            suspicious_commands = results.get('suspicious_commands', [])
            
            # Statistiques par shell
            shell_stats = {}
            for entry in entries:
                shell_type = entry.get('shell_type', 'unknown')
                shell_stats[shell_type] = shell_stats.get(shell_type, 0) + 1
            
            # Statistiques par utilisateur
            user_stats = {}
            for entry in entries:
                username = entry.get('username', 'unknown')
                if username not in user_stats:
                    user_stats[username] = {
                        'total_commands': 0,
                        'shells_used': set(),
                        'last_command': None
                    }
                user_stats[username]['total_commands'] += 1
                user_stats[username]['shells_used'].add(entry.get('shell_type', 'unknown'))
                
                # Convertir les ensembles en listes pour la sérialisation JSON
                user_stats[username]['shells_used'] = list(user_stats[username]['shells_used'])
            
            return {
                'total_entries': len(entries),
                'users_analyzed_count': len(users_analyzed),
                'suspicious_commands_count': len(suspicious_commands),
                'high_risk_commands': len([cmd for cmd in suspicious_commands if cmd.get('risk_level') == 'high']),
                'medium_risk_commands': len([cmd for cmd in suspicious_commands if cmd.get('risk_level') == 'medium']),
                'low_risk_commands': len([cmd for cmd in suspicious_commands if cmd.get('risk_level') == 'low']),
                'shell_statistics': shell_stats,
                'user_statistics': user_stats,
                'files_with_timestamps': len([entry for entry in entries if entry.get('timestamp')])
            }
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la génération du résumé: {e}")
            return {'error': str(e)} 