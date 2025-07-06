"""
Collecteur pour les utilisateurs Linux
Collecte les informations sur les utilisateurs et groupes
"""

import os
import re
from datetime import datetime
from typing import Dict, List, Any
from .base import LinuxCollector

class UsersCollector(LinuxCollector):
    """Collecteur pour les utilisateurs Linux (multi-OS safe)"""
    
    def __init__(self):
        super().__init__()
    
    def _geteuid(self):
        # Méthode utilitaire multi-OS
        try:
            return os.geteuid()
        except AttributeError:
            return 0  # Par défaut, root sur Windows ou OS sans geteuid
    
    def collect(self) -> Dict[str, Any]:
        """Collecte les informations sur les utilisateurs"""
        results = {
            'system_info': self.get_system_info(),
            'users': [],
            'groups': [],
            'suspicious_users': [],
            'privileged_users': [],
            'recent_logins': [],
            'summary': {}
        }
        
        # Collecter les utilisateurs
        results['users'] = self._collect_users()
        
        # Collecter les groupes
        results['groups'] = self._collect_groups()
        
        # Analyser les utilisateurs suspects
        results['suspicious_users'] = self._analyze_suspicious_users(results['users'])
        
        # Collecter les utilisateurs privilégiés
        results['privileged_users'] = self._collect_privileged_users(results['users'])
        
        # Collecter les connexions récentes
        results['recent_logins'] = self._collect_recent_logins()
        
        # Générer un résumé
        results['summary'] = self._generate_summary(results)
        
        return results
    
    def _collect_users(self) -> List[Dict[str, Any]]:
        """Collecte les informations sur les utilisateurs"""
        users = []
        
        try:
            # Lire /etc/passwd si dispo
            if os.path.exists('/etc/passwd'):
                with open('/etc/passwd', 'r') as f:
                    for line in f:
                        if line.strip():
                            user_info = self._parse_passwd_line(line)
                            if user_info:
                                users.append(user_info)
            else:
                self.logger.warning("/etc/passwd non disponible sur ce système.")
                return users
            # Enrichir avec les informations de /etc/shadow (si root et dispo)
            if self._geteuid() == 0 and os.path.exists('/etc/shadow'):
                shadow_info = self._collect_shadow_info()
                for user in users:
                    username = user.get('username')
                    if username in shadow_info:
                        user.update(shadow_info[username])
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte des utilisateurs: {e}")
        
        return users
    
    def _parse_passwd_line(self, line: str) -> Dict[str, Any]:
        """Parse une ligne de /etc/passwd"""
        try:
            parts = line.strip().split(':')
            if len(parts) >= 7:
                return {
                    'username': parts[0],
                    'password': parts[1],
                    'uid': int(parts[2]),
                    'gid': int(parts[3]),
                    'gecos': parts[4],
                    'home_directory': parts[5],
                    'shell': parts[6],
                    'has_password': parts[1] != 'x' and parts[1] != '*',
                    'is_system_user': int(parts[2]) < 1000,
                    'is_root': int(parts[2]) == 0
                }
        except Exception as e:
            self.logger.error(f"Erreur lors du parsing de la ligne passwd: {line[:50]}... - {e}")
        
        return None
    
    def _collect_shadow_info(self) -> Dict[str, Dict[str, Any]]:
        """Collecte les informations de /etc/shadow"""
        shadow_info = {}
        
        try:
            with open('/etc/shadow', 'r') as f:
                for line in f:
                    if line.strip():
                        parts = line.strip().split(':')
                        if len(parts) >= 9:
                            username = parts[0]
                            shadow_info[username] = {
                                'password_hash': parts[1],
                                'last_password_change': self._parse_shadow_date(parts[2]),
                                'min_password_age': int(parts[3]) if parts[3] else -1,
                                'max_password_age': int(parts[4]) if parts[4] else -1,
                                'password_warning_period': int(parts[5]) if parts[5] else -1,
                                'password_inactivity_period': int(parts[6]) if parts[6] else -1,
                                'account_expiration': self._parse_shadow_date(parts[7]),
                                'account_locked': parts[1].startswith('!') or parts[1].startswith('*'),
                                'password_expired': parts[1] == '!!'
                            }
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte des informations shadow: {e}")
        
        return shadow_info
    
    def _parse_shadow_date(self, date_str: str) -> str:
        """Parse une date shadow (jours depuis 1970-01-01)"""
        try:
            if date_str and date_str != '':
                days = int(date_str)
                if days > 0:
                    date = datetime(1970, 1, 1) + datetime.timedelta(days=days)
                    return date.isoformat()
        except:
            pass
        return None
    
    def _collect_groups(self) -> List[Dict[str, Any]]:
        """Collecte les informations sur les groupes"""
        groups = []
        try:
            if os.path.exists('/etc/group'):
                with open('/etc/group', 'r') as f:
                    for line in f:
                        if line.strip():
                            group_info = self._parse_group_line(line)
                            if group_info:
                                groups.append(group_info)
            else:
                self.logger.warning("/etc/group non disponible sur ce système.")
                return groups
            # Enrichir avec /etc/gshadow (si root et dispo)
            if self._geteuid() == 0 and os.path.exists('/etc/gshadow'):
                gshadow_info = self._collect_gshadow_info()
                for group in groups:
                    groupname = group.get('groupname')
                    if groupname in gshadow_info:
                        group.update(gshadow_info[groupname])
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte des groupes: {e}")
        return groups
    
    def _parse_group_line(self, line: str) -> Dict[str, Any]:
        """Parse une ligne de /etc/group"""
        try:
            parts = line.strip().split(':')
            if len(parts) >= 4:
                members = parts[3].split(',') if parts[3] else []
                return {
                    'groupname': parts[0],
                    'password': parts[1],
                    'gid': int(parts[2]),
                    'members': [m for m in members if m],
                    'is_system_group': int(parts[2]) < 1000,
                    'is_root_group': int(parts[2]) == 0
                }
        except Exception as e:
            self.logger.error(f"Erreur lors du parsing de la ligne group: {line[:50]}... - {e}")
        
        return None
    
    def _collect_gshadow_info(self) -> Dict[str, Dict[str, Any]]:
        """Collecte les informations de /etc/gshadow"""
        gshadow_info = {}
        
        try:
            with open('/etc/gshadow', 'r') as f:
                for line in f:
                    if line.strip():
                        parts = line.strip().split(':')
                        if len(parts) >= 4:
                            groupname = parts[0]
                            gshadow_info[groupname] = {
                                'password_hash': parts[1],
                                'administrators': parts[2].split(',') if parts[2] else [],
                                'members': parts[3].split(',') if parts[3] else [],
                                'has_password': parts[1] != '!' and parts[1] != '*'
                            }
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte des informations gshadow: {e}")
        
        return gshadow_info
    
    def _analyze_suspicious_users(self, users: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyse les utilisateurs suspects"""
        suspicious_users = []
        
        # Patterns de noms d'utilisateurs suspects
        suspicious_patterns = [
            r'\b(backdoor|trojan|malware|virus)\b',
            r'\b(keylogger|logger|spy)\b',
            r'\b(exploit|payload|shell)\b',
            r'\b(bot|botnet)\b',
            r'\b(miner|mining)\b',
            r'\b(stealer|spyware)\b',
            r'\b(rootkit|bootkit)\b',
            r'\b(test|temp|tmp|admin|root)\b'
        ]
        
        # Compiler les patterns
        compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in suspicious_patterns]
        
        for user in users:
            suspicious_flags = []
            username = user.get('username', '')
            
            # Vérifier le nom d'utilisateur
            for pattern in compiled_patterns:
                if pattern.search(username):
                    suspicious_flags.append(f"Nom suspect: {username}")
            
            # Vérifier les UID suspects
            uid = user.get('uid', 0)
            if uid == 0 and username != 'root':
                suspicious_flags.append(f"UID root (0) pour un utilisateur non-root: {username}")
            elif uid < 1000 and not user.get('is_system_user', False):
                suspicious_flags.append(f"UID système ({uid}) pour un utilisateur non-système: {username}")
            
            # Vérifier les shells suspects
            shell = user.get('shell', '')
            if shell in ['/bin/bash', '/bin/sh'] and user.get('is_system_user', False):
                suspicious_flags.append(f"Shell interactif pour un utilisateur système: {shell}")
            
            # Vérifier les répertoires home suspects
            home_dir = user.get('home_directory', '')
            if home_dir in ['/tmp', '/var/tmp', '/dev/shm']:
                suspicious_flags.append(f"Répertoire home suspect: {home_dir}")
            
            # Vérifier les mots de passe
            if not user.get('has_password', False):
                suspicious_flags.append("Aucun mot de passe défini")
            
            # Vérifier les comptes verrouillés
            if user.get('account_locked', False):
                suspicious_flags.append("Compte verrouillé")
            
            # Vérifier les mots de passe expirés
            if user.get('password_expired', False):
                suspicious_flags.append("Mot de passe expiré")
            
            # Si des flags suspects sont trouvés
            if suspicious_flags:
                suspicious_users.append({
                    'user_info': user,
                    'suspicious_flags': suspicious_flags,
                    'risk_level': self._assess_user_risk(suspicious_flags)
                })
        
        return suspicious_users
    
    def _assess_user_risk(self, flags: List[str]) -> str:
        """Évalue le niveau de risque d'un utilisateur"""
        high_risk_flags = [
            "Nom suspect:",
            "UID root (0) pour un utilisateur non-root:",
            "Aucun mot de passe défini",
            "Répertoire home suspect:"
        ]
        
        medium_risk_flags = [
            "UID système",
            "Shell interactif pour un utilisateur système:",
            "Compte verrouillé",
            "Mot de passe expiré"
        ]
        
        if any(any(high_flag in flag for high_flag in high_risk_flags) for flag in flags):
            return 'high'
        elif any(any(medium_flag in flag for medium_flag in medium_risk_flags) for flag in flags):
            return 'medium'
        else:
            return 'low'
    
    def _collect_privileged_users(self, users: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Collecte les utilisateurs privilégiés"""
        privileged_users = []
        
        for user in users:
            privileges = []
            
            # Vérifier les privilèges sudo
            if self._has_sudo_privileges(user.get('username', '')):
                privileges.append('sudo')
            
            # Vérifier les groupes privilégiés
            privileged_groups = self._get_privileged_groups(user.get('username', ''))
            if privileged_groups:
                privileges.extend(privileged_groups)
            
            # Vérifier les capacités Linux
            capabilities = self._get_user_capabilities(user.get('username', ''))
            if capabilities:
                privileges.append(f"capabilities: {capabilities}")
            
            # Vérifier les fichiers SUID/SGID
            suid_files = self._get_user_suid_files(user.get('username', ''))
            if suid_files:
                privileges.append(f"SUID files: {len(suid_files)}")
            
            if privileges:
                privileged_users.append({
                    'user_info': user,
                    'privileges': privileges
                })
        
        return privileged_users
    
    def _has_sudo_privileges(self, username: str) -> bool:
        """Vérifie si un utilisateur a des privilèges sudo"""
        try:
            result = self.execute_command(['sudo', '-l', '-U', username])
            return result['success'] and 'ALL' in result['stdout']
        except:
            return False
    
    def _get_privileged_groups(self, username: str) -> List[str]:
        """Obtient les groupes privilégiés d'un utilisateur"""
        privileged_groups = []
        
        try:
            result = self.execute_command(['groups', username])
            if result['success']:
                groups = result['stdout'].split(':')[1].strip().split()
                privileged_groups = [g for g in groups if g in ['sudo', 'wheel', 'admin', 'root']]
        except:
            pass
        
        return privileged_groups
    
    def _get_user_capabilities(self, username: str) -> List[str]:
        """Obtient les capacités Linux d'un utilisateur"""
        capabilities = []
        
        try:
            # Vérifier les capacités dans /proc/[pid]/status
            for proc in os.listdir('/proc'):
                if proc.isdigit():
                    try:
                        with open(f'/proc/{proc}/status', 'r') as f:
                            for line in f:
                                if line.startswith('Cap'):
                                    # Parse les capacités
                                    pass
                    except:
                        continue
        except:
            pass
        
        return capabilities
    
    def _get_user_suid_files(self, username: str) -> List[str]:
        """Obtient les fichiers SUID appartenant à un utilisateur"""
        suid_files = []
        
        try:
            result = self.execute_command([
                'find', '/', '-type', 'f', '-perm', '-4000', '-user', username,
                '-not', '-path', '/proc/*', '-not', '-path', '/sys/*'
            ], timeout=30)
            
            if result['success']:
                suid_files = result['stdout'].split('\n')
                suid_files = [f for f in suid_files if f.strip()]
        except:
            pass
        
        return suid_files
    
    def _collect_recent_logins(self) -> List[Dict[str, Any]]:
        """Collecte les connexions récentes"""
        recent_logins = []
        
        try:
            # Utiliser la commande last
            result = self.execute_command(['last', '-n', '50'])
            
            if result['success']:
                lines = result['stdout'].split('\n')
                
                for line in lines:
                    if line.strip() and not line.startswith('wtmp'):
                        # Parse: username pts/0 192.168.1.100 Mon Jan 15 10:30 - 11:45 (01:15)
                        parts = line.split()
                        if len(parts) >= 4:
                            login_info = {
                                'username': parts[0],
                                'terminal': parts[1],
                                'host': parts[2],
                                'login_time': ' '.join(parts[3:7]) if len(parts) >= 7 else '',
                                'duration': parts[-1] if parts[-1].startswith('(') else '',
                                'raw_line': line
                            }
                            recent_logins.append(login_info)
            
            # Utiliser la commande who
            result = self.execute_command(['who'])
            
            if result['success']:
                current_users = []
                for line in result['stdout'].split('\n'):
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 4:
                            current_users.append({
                                'username': parts[0],
                                'terminal': parts[1],
                                'login_time': ' '.join(parts[2:4]),
                                'host': parts[4] if len(parts) > 4 else '',
                                'raw_line': line
                            })
                
                recent_logins.append({
                    'type': 'current_users',
                    'users': current_users
                })
        
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte des connexions récentes: {e}")
        
        return recent_logins
    
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Génère un résumé des utilisateurs"""
        try:
            users = results.get('users', [])
            groups = results.get('groups', [])
            suspicious_users = results.get('suspicious_users', [])
            privileged_users = results.get('privileged_users', [])
            recent_logins = results.get('recent_logins', [])
            
            # Statistiques des utilisateurs
            user_stats = {
                'total_users': len(users),
                'system_users': len([u for u in users if u.get('is_system_user', False)]),
                'regular_users': len([u for u in users if not u.get('is_system_user', False)]),
                'users_with_password': len([u for u in users if u.get('has_password', False)]),
                'users_without_password': len([u for u in users if not u.get('has_password', False)]),
                'locked_accounts': len([u for u in users if u.get('account_locked', False)])
            }
            
            # Statistiques des groupes
            group_stats = {
                'total_groups': len(groups),
                'system_groups': len([g for g in groups if g.get('is_system_group', False)]),
                'regular_groups': len([g for g in groups if not g.get('is_system_group', False)])
            }
            
            # Statistiques des utilisateurs suspects
            suspicious_stats = {
                'total_suspicious_users': len(suspicious_users),
                'high_risk_users': len([u for u in suspicious_users if u.get('risk_level') == 'high']),
                'medium_risk_users': len([u for u in suspicious_users if u.get('risk_level') == 'medium']),
                'low_risk_users': len([u for u in suspicious_users if u.get('risk_level') == 'low'])
            }
            
            return {
                'user_statistics': user_stats,
                'group_statistics': group_stats,
                'suspicious_users_statistics': suspicious_stats,
                'privileged_users_count': len(privileged_users),
                'recent_logins_count': len([l for l in recent_logins if l.get('type') != 'current_users']),
                'current_users_count': len(recent_logins[-1].get('users', [])) if recent_logins and recent_logins[-1].get('type') == 'current_users' else 0
            }
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la génération du résumé: {e}")
            return {'error': str(e)} 