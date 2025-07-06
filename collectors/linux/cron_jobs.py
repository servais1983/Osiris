"""
Collecteur pour les tâches cron Linux
Collecte les tâches cron système et utilisateur
"""

import os
import re
from datetime import datetime
from typing import Dict, List, Any
from .base import LinuxCollector

class CronJobsCollector(LinuxCollector):
    """Collecteur pour les tâches cron Linux"""
    
    def __init__(self):
        super().__init__()
    
    def collect(self) -> Dict[str, Any]:
        """Collecte les tâches cron"""
        results = {
            'system_info': self.get_system_info(),
            'system_crontab': {},
            'user_crontabs': {},
            'cron_directories': {},
            'suspicious_jobs': [],
            'summary': {}
        }
        
        # Collecter le crontab système
        results['system_crontab'] = self._collect_system_crontab()
        
        # Collecter les crontabs utilisateur
        results['user_crontabs'] = self._collect_user_crontabs()
        
        # Collecter les répertoires cron
        results['cron_directories'] = self._collect_cron_directories()
        
        # Analyser les tâches suspectes
        results['suspicious_jobs'] = self._analyze_suspicious_jobs(results)
        
        # Générer un résumé
        results['summary'] = self._generate_summary(results)
        
        return results
    
    def _collect_system_crontab(self) -> Dict[str, Any]:
        """Collecte le crontab système"""
        system_crontab = {}
        
        try:
            # Lire /etc/crontab
            if os.path.exists('/etc/crontab'):
                system_crontab['file_info'] = self.get_file_info('/etc/crontab')
                system_crontab['content'] = self.read_file_lines('/etc/crontab')
                system_crontab['jobs'] = self._parse_crontab_content(system_crontab['content'])
            
            # Lire /etc/anacrontab
            if os.path.exists('/etc/anacrontab'):
                system_crontab['anacrontab'] = {
                    'file_info': self.get_file_info('/etc/anacrontab'),
                    'content': self.read_file_lines('/etc/anacrontab'),
                    'jobs': self._parse_anacrontab_content(system_crontab.get('anacrontab', {}).get('content', []))
                }
        
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte du crontab système: {e}")
            system_crontab['error'] = str(e)
        
        return system_crontab
    
    def _collect_user_crontabs(self) -> Dict[str, Any]:
        """Collecte les crontabs utilisateur"""
        user_crontabs = {}
        
        try:
            # Utiliser crontab -l pour chaque utilisateur
            if os.geteuid() == 0:
                # En tant que root, on peut accéder à tous les crontabs
                result = self.execute_command(['find', '/var/spool/cron/crontabs', '-name', '*'])
                
                if result['success']:
                    for line in result['stdout'].split('\n'):
                        if line.strip():
                            username = os.path.basename(line.strip())
                            crontab_content = self._get_user_crontab(username)
                            if crontab_content:
                                user_crontabs[username] = {
                                    'content': crontab_content,
                                    'jobs': self._parse_crontab_content(crontab_content)
                                }
            else:
                # Utilisateur normal, seulement son propre crontab
                current_user = os.getlogin()
                crontab_content = self._get_user_crontab(current_user)
                if crontab_content:
                    user_crontabs[current_user] = {
                        'content': crontab_content,
                        'jobs': self._parse_crontab_content(crontab_content)
                    }
        
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte des crontabs utilisateur: {e}")
            user_crontabs['error'] = str(e)
        
        return user_crontabs
    
    def _get_user_crontab(self, username: str) -> List[str]:
        """Obtient le crontab d'un utilisateur spécifique"""
        try:
            if os.geteuid() == 0:
                # En tant que root, lire directement le fichier
                crontab_path = f'/var/spool/cron/crontabs/{username}'
                if os.path.exists(crontab_path):
                    return self.read_file_lines(crontab_path)
            else:
                # Utilisateur normal, utiliser crontab -l
                result = self.execute_command(['crontab', '-l', '-u', username])
                if result['success']:
                    return result['stdout'].split('\n')
        except:
            pass
        
        return []
    
    def _collect_cron_directories(self) -> Dict[str, Any]:
        """Collecte les répertoires cron"""
        cron_directories = {}
        
        cron_dirs = [
            '/etc/cron.d',
            '/etc/cron.daily',
            '/etc/cron.hourly',
            '/etc/cron.monthly',
            '/etc/cron.weekly'
        ]
        
        for cron_dir in cron_dirs:
            if os.path.exists(cron_dir):
                cron_directories[cron_dir] = self._analyze_cron_directory(cron_dir)
        
        return cron_directories
    
    def _analyze_cron_directory(self, directory: str) -> Dict[str, Any]:
        """Analyse un répertoire cron"""
        dir_info = {
            'directory': directory,
            'files': [],
            'executable_files': []
        }
        
        try:
            for item in os.listdir(directory):
                item_path = os.path.join(directory, item)
                
                if os.path.isfile(item_path):
                    file_info = {
                        'name': item,
                        'path': item_path,
                        'file_info': self.get_file_info(item_path),
                        'is_executable': os.access(item_path, os.X_OK),
                        'content': self.read_file_lines(item_path) if item.endswith(('.cron', '.tab')) else None
                    }
                    
                    dir_info['files'].append(file_info)
                    
                    if file_info['is_executable']:
                        dir_info['executable_files'].append(file_info)
        
        except Exception as e:
            dir_info['error'] = str(e)
        
        return dir_info
    
    def _parse_crontab_content(self, content: List[str]) -> List[Dict[str, Any]]:
        """Parse le contenu d'un crontab"""
        jobs = []
        
        for line in content:
            line = line.strip()
            
            # Ignorer les commentaires et les lignes vides
            if not line or line.startswith('#'):
                continue
            
            # Parse: minute hour day month weekday command
            parts = line.split()
            if len(parts) >= 6:
                job = {
                    'minute': parts[0],
                    'hour': parts[1],
                    'day': parts[2],
                    'month': parts[3],
                    'weekday': parts[4],
                    'command': ' '.join(parts[5:]),
                    'raw_line': line
                }
                
                # Analyser les champs de temps
                job['time_analysis'] = self._analyze_cron_time(job)
                
                jobs.append(job)
        
        return jobs
    
    def _parse_anacrontab_content(self, content: List[str]) -> List[Dict[str, Any]]:
        """Parse le contenu d'un anacrontab"""
        jobs = []
        
        for line in content:
            line = line.strip()
            
            # Ignorer les commentaires et les lignes vides
            if not line or line.startswith('#'):
                continue
            
            # Parse: period delay job-identifier command
            parts = line.split()
            if len(parts) >= 4:
                job = {
                    'period': parts[0],
                    'delay': parts[1],
                    'job_identifier': parts[2],
                    'command': ' '.join(parts[3:]),
                    'raw_line': line
                }
                
                jobs.append(job)
        
        return jobs
    
    def _analyze_cron_time(self, job: Dict[str, Any]) -> Dict[str, Any]:
        """Analyse les champs de temps d'une tâche cron"""
        time_analysis = {}
        
        for field in ['minute', 'hour', 'day', 'month', 'weekday']:
            value = job.get(field, '')
            
            if value == '*':
                time_analysis[f'{field}_type'] = 'any'
            elif '/' in value:
                time_analysis[f'{field}_type'] = 'step'
                step_parts = value.split('/')
                time_analysis[f'{field}_step'] = int(step_parts[1])
            elif ',' in value:
                time_analysis[f'{field}_type'] = 'list'
                time_analysis[f'{field}_values'] = [int(x) for x in value.split(',')]
            elif '-' in value:
                time_analysis[f'{field}_type'] = 'range'
                range_parts = value.split('-')
                time_analysis[f'{field}_range'] = [int(range_parts[0]), int(range_parts[1])]
            else:
                try:
                    time_analysis[f'{field}_type'] = 'specific'
                    time_analysis[f'{field}_value'] = int(value)
                except:
                    time_analysis[f'{field}_type'] = 'invalid'
        
        return time_analysis
    
    def _analyze_suspicious_jobs(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyse les tâches cron suspectes"""
        suspicious_jobs = []
        
        # Patterns de commandes suspectes
        suspicious_patterns = [
            r'\b(wget|curl)\s+.*\b(http|https)://',
            r'\b(nc|netcat)\s+.*\b(connect|listen)',
            r'\b(ssh|scp)\s+.*\b(root@|admin@)',
            r'\b(sudo|su)\s+.*\b(root|admin)',
            r'\b(chmod|chown)\s+.*\b777|666',
            r'\b(rm|del)\s+.*\b(-rf|/rf)',
            r'\b(passwd|password)\s+.*\b(root|admin)',
            r'\b(service|systemctl)\s+.*\b(stop|disable)',
            r'\b(ufw|iptables)\s+.*\b(disable|stop)',
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
        
        # Analyser les tâches système
        system_jobs = results.get('system_crontab', {}).get('jobs', [])
        for job in system_jobs:
            suspicious_flags = self._check_job_suspicious(job, compiled_patterns)
            if suspicious_flags:
                suspicious_jobs.append({
                    'job': job,
                    'source': 'system_crontab',
                    'suspicious_flags': suspicious_flags,
                    'risk_level': self._assess_job_risk(suspicious_flags)
                })
        
        # Analyser les tâches utilisateur
        for username, user_crontab in results.get('user_crontabs', {}).items():
            if isinstance(user_crontab, dict) and 'jobs' in user_crontab:
                for job in user_crontab['jobs']:
                    suspicious_flags = self._check_job_suspicious(job, compiled_patterns)
                    if suspicious_flags:
                        suspicious_jobs.append({
                            'job': job,
                            'source': f'user_crontab:{username}',
                            'suspicious_flags': suspicious_flags,
                            'risk_level': self._assess_job_risk(suspicious_flags)
                        })
        
        # Analyser les fichiers dans les répertoires cron
        for dir_path, dir_info in results.get('cron_directories', {}).items():
            if isinstance(dir_info, dict) and 'files' in dir_info:
                for file_info in dir_info['files']:
                    if file_info.get('content'):
                        for line in file_info['content']:
                            if line.strip() and not line.startswith('#'):
                                # Créer un job factice pour l'analyse
                                job = {
                                    'command': line.strip(),
                                    'raw_line': line.strip(),
                                    'source_file': file_info['path']
                                }
                                suspicious_flags = self._check_job_suspicious(job, compiled_patterns)
                                if suspicious_flags:
                                    suspicious_jobs.append({
                                        'job': job,
                                        'source': f'cron_directory:{dir_path}',
                                        'suspicious_flags': suspicious_flags,
                                        'risk_level': self._assess_job_risk(suspicious_flags)
                                    })
        
        return suspicious_jobs
    
    def _check_job_suspicious(self, job: Dict[str, Any], patterns: List[re.Pattern]) -> List[str]:
        """Vérifie si une tâche est suspecte"""
        suspicious_flags = []
        command = job.get('command', '')
        
        # Vérifier les patterns suspects
        for pattern in patterns:
            if pattern.search(command):
                suspicious_flags.append(f"Commande suspecte: {pattern.pattern}")
        
        # Vérifier les tâches qui s'exécutent très fréquemment
        time_analysis = job.get('time_analysis', {})
        if time_analysis.get('minute_type') == 'any' and time_analysis.get('hour_type') == 'any':
            suspicious_flags.append("Exécution très fréquente (toutes les minutes)")
        elif time_analysis.get('minute_type') == 'step' and time_analysis.get('minute_step', 0) < 5:
            suspicious_flags.append("Exécution très fréquente (toutes les X minutes)")
        
        # Vérifier les tâches qui s'exécutent à des heures suspectes
        hour_value = time_analysis.get('hour_value')
        if hour_value is not None and (hour_value < 6 or hour_value > 22):
            suspicious_flags.append(f"Exécution à des heures suspectes: {hour_value}h")
        
        # Vérifier les commandes qui utilisent des chemins absolus suspects
        if any(path in command for path in ['/tmp/', '/var/tmp/', '/dev/shm/']):
            suspicious_flags.append("Utilisation de répertoires temporaires")
        
        # Vérifier les redirections suspectes
        if '>/dev/null' in command or '2>/dev/null' in command:
            suspicious_flags.append("Redirection vers /dev/null (masquage de sortie)")
        
        return suspicious_flags
    
    def _assess_job_risk(self, flags: List[str]) -> str:
        """Évalue le niveau de risque d'une tâche cron"""
        high_risk_flags = [
            "Commande suspecte:",
            "Exécution très fréquente",
            "Utilisation de répertoires temporaires"
        ]
        
        medium_risk_flags = [
            "Exécution à des heures suspectes:",
            "Redirection vers /dev/null"
        ]
        
        if any(any(high_flag in flag for high_flag in high_risk_flags) for flag in flags):
            return 'high'
        elif any(any(medium_flag in flag for medium_flag in medium_risk_flags) for flag in flags):
            return 'medium'
        else:
            return 'low'
    
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Génère un résumé des tâches cron"""
        try:
            system_crontab = results.get('system_crontab', {})
            user_crontabs = results.get('user_crontabs', {})
            cron_directories = results.get('cron_directories', {})
            suspicious_jobs = results.get('suspicious_jobs', [])
            
            # Statistiques des tâches système
            system_stats = {
                'system_jobs_count': len(system_crontab.get('jobs', [])),
                'anacron_jobs_count': len(system_crontab.get('anacrontab', {}).get('jobs', []))
            }
            
            # Statistiques des tâches utilisateur
            user_stats = {
                'users_with_crontab': len([u for u in user_crontabs.keys() if isinstance(user_crontabs[u], dict)]),
                'total_user_jobs': sum(len(user_crontabs[u].get('jobs', [])) for u in user_crontabs.keys() if isinstance(user_crontabs[u], dict))
            }
            
            # Statistiques des répertoires cron
            directory_stats = {
                'total_directories': len(cron_directories),
                'total_files': sum(len(d.get('files', [])) for d in cron_directories.values() if isinstance(d, dict)),
                'executable_files': sum(len(d.get('executable_files', [])) for d in cron_directories.values() if isinstance(d, dict))
            }
            
            # Statistiques des tâches suspectes
            suspicious_stats = {
                'total_suspicious_jobs': len(suspicious_jobs),
                'high_risk_jobs': len([j for j in suspicious_jobs if j.get('risk_level') == 'high']),
                'medium_risk_jobs': len([j for j in suspicious_jobs if j.get('risk_level') == 'medium']),
                'low_risk_jobs': len([j for j in suspicious_jobs if j.get('risk_level') == 'low'])
            }
            
            return {
                'system_cron_statistics': system_stats,
                'user_cron_statistics': user_stats,
                'cron_directory_statistics': directory_stats,
                'suspicious_jobs_statistics': suspicious_stats,
                'total_jobs_analyzed': system_stats['system_jobs_count'] + user_stats['total_user_jobs']
            }
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la génération du résumé: {e}")
            return {'error': str(e)} 