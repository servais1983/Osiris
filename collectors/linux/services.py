"""
Collecteur pour les services Linux
Collecte les informations sur les services systemd et init.d
"""

import os
import re
from datetime import datetime
from typing import Dict, List, Any
from .base import LinuxCollector

class ServicesCollector(LinuxCollector):
    """Collecteur pour les services Linux"""
    
    def __init__(self):
        super().__init__()
    
    def collect(self) -> Dict[str, Any]:
        """Collecte les informations sur les services"""
        results = {
            'system_info': self.get_system_info(),
            'systemd_services': {},
            'init_services': {},
            'running_services': [],
            'failed_services': [],
            'suspicious_services': [],
            'summary': {}
        }
        
        # Collecter les services systemd
        results['systemd_services'] = self._collect_systemd_services()
        
        # Collecter les services init.d
        results['init_services'] = self._collect_init_services()
        
        # Collecter les services en cours d'exécution
        results['running_services'] = self._collect_running_services()
        
        # Collecter les services en échec
        results['failed_services'] = self._collect_failed_services()
        
        # Analyser les services suspects
        results['suspicious_services'] = self._analyze_suspicious_services(results)
        
        # Générer un résumé
        results['summary'] = self._generate_summary(results)
        
        return results
    
    def _collect_systemd_services(self) -> Dict[str, Any]:
        """Collecte les services systemd"""
        systemd_services = {}
        
        try:
            # Lister tous les services systemd
            result = self.execute_command(['systemctl', 'list-units', '--type=service', '--all'])
            
            if result['success']:
                lines = result['stdout'].split('\n')
                
                for line in lines:
                    if line.strip() and not line.startswith('UNIT'):
                        # Parse: ssh.service loaded active running OpenBSD Secure Shell server
                        parts = line.split()
                        if len(parts) >= 4:
                            service_name = parts[0]
                            load_state = parts[1]
                            active_state = parts[2]
                            sub_state = parts[3]
                            description = ' '.join(parts[4:]) if len(parts) > 4 else ''
                            
                            # Obtenir des informations détaillées sur le service
                            service_details = self._get_systemd_service_details(service_name)
                            
                            systemd_services[service_name] = {
                                'load_state': load_state,
                                'active_state': active_state,
                                'sub_state': sub_state,
                                'description': description,
                                'details': service_details
                            }
            
            # Collecter les services activés
            result = self.execute_command(['systemctl', 'list-unit-files', '--type=service'])
            
            if result['success']:
                lines = result['stdout'].split('\n')
                
                for line in lines:
                    if line.strip() and not line.startswith('UNIT'):
                        parts = line.split()
                        if len(parts) >= 2:
                            service_name = parts[0]
                            state = parts[1]
                            
                            if service_name in systemd_services:
                                systemd_services[service_name]['unit_file_state'] = state
        
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte des services systemd: {e}")
        
        return systemd_services
    
    def _get_systemd_service_details(self, service_name: str) -> Dict[str, Any]:
        """Obtient les détails d'un service systemd"""
        details = {}
        
        try:
            # Obtenir le statut détaillé
            result = self.execute_command(['systemctl', 'show', service_name])
            
            if result['success']:
                for line in result['stdout'].split('\n'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        details[key.strip()] = value.strip()
            
            # Obtenir les logs récents
            result = self.execute_command(['journalctl', '-u', service_name, '--no-pager', '-n', '10'])
            
            if result['success']:
                details['recent_logs'] = result['stdout'].split('\n')[:10]
        
        except Exception as e:
            self.logger.error(f"Erreur lors de l'obtention des détails pour {service_name}: {e}")
        
        return details
    
    def _collect_init_services(self) -> Dict[str, Any]:
        """Collecte les services init.d"""
        init_services = {}
        
        try:
            # Lister les services init.d
            init_d_path = '/etc/init.d'
            
            if os.path.exists(init_d_path):
                for service_file in os.listdir(init_d_path):
                    service_path = os.path.join(init_d_path, service_file)
                    
                    if os.path.isfile(service_path) and os.access(service_path, os.X_OK):
                        service_info = self._analyze_init_service(service_path)
                        init_services[service_file] = service_info
        
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte des services init.d: {e}")
        
        return init_services
    
    def _analyze_init_service(self, service_path: str) -> Dict[str, Any]:
        """Analyse un service init.d"""
        service_info = {
            'path': service_path,
            'file_info': self.get_file_info(service_path),
            'status': 'unknown'
        }
        
        try:
            # Tester le statut du service
            result = self.execute_command([service_path, 'status'])
            
            if result['success']:
                service_info['status'] = 'running'
                service_info['status_output'] = result['stdout']
            else:
                service_info['status'] = 'stopped'
                service_info['status_output'] = result['stderr']
            
            # Lire le contenu du script
            try:
                with open(service_path, 'r') as f:
                    content = f.read()
                    service_info['content_preview'] = content[:1000]  # Premiers 1000 caractères
                    
                    # Extraire les informations du script
                    service_info['script_info'] = self._extract_script_info(content)
            except:
                pass
        
        except Exception as e:
            service_info['error'] = str(e)
        
        return service_info
    
    def _extract_script_info(self, content: str) -> Dict[str, Any]:
        """Extrait les informations d'un script init.d"""
        script_info = {}
        
        try:
            # Chercher la description
            desc_match = re.search(r'DESCRIPTION="([^"]+)"', content)
            if desc_match:
                script_info['description'] = desc_match.group(1)
            
            # Chercher le nom du service
            name_match = re.search(r'NAME="([^"]+)"', content)
            if name_match:
                script_info['name'] = name_match.group(1)
            
            # Chercher le daemon
            daemon_match = re.search(r'DAEMON="([^"]+)"', content)
            if daemon_match:
                script_info['daemon'] = daemon_match.group(1)
            
            # Chercher les dépendances
            depends_match = re.search(r'REQUIRED="([^"]+)"', content)
            if depends_match:
                script_info['required'] = depends_match.group(1)
        
        except Exception as e:
            script_info['error'] = str(e)
        
        return script_info
    
    def _collect_running_services(self) -> List[Dict[str, Any]]:
        """Collecte les services en cours d'exécution"""
        running_services = []
        
        try:
            # Utiliser systemctl pour les services actifs
            result = self.execute_command(['systemctl', 'list-units', '--type=service', '--state=running'])
            
            if result['success']:
                lines = result['stdout'].split('\n')
                
                for line in lines:
                    if line.strip() and not line.startswith('UNIT'):
                        parts = line.split()
                        if len(parts) >= 4:
                            service_name = parts[0]
                            description = ' '.join(parts[4:]) if len(parts) > 4 else ''
                            
                            # Obtenir le PID du service
                            pid_info = self._get_service_pid(service_name)
                            
                            running_services.append({
                                'name': service_name,
                                'description': description,
                                'pid': pid_info.get('pid'),
                                'main_pid': pid_info.get('main_pid'),
                                'memory_usage': pid_info.get('memory_usage'),
                                'cpu_usage': pid_info.get('cpu_usage')
                            })
        
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte des services en cours d'exécution: {e}")
        
        return running_services
    
    def _get_service_pid(self, service_name: str) -> Dict[str, Any]:
        """Obtient le PID d'un service"""
        pid_info = {}
        
        try:
            result = self.execute_command(['systemctl', 'show', service_name, '--property=MainPID,MemoryCurrent,CPUUsageNSec'])
            
            if result['success']:
                for line in result['stdout'].split('\n'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        if key == 'MainPID':
                            pid_info['main_pid'] = int(value) if value != '0' else None
                        elif key == 'MemoryCurrent':
                            pid_info['memory_usage'] = int(value) if value != '0' else 0
                        elif key == 'CPUUsageNSec':
                            pid_info['cpu_usage'] = int(value) if value != '0' else 0
            
            # Obtenir tous les PIDs du service
            result = self.execute_command(['systemctl', 'show', service_name, '--property=ExecMainPID'])
            
            if result['success']:
                for line in result['stdout'].split('\n'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        if key == 'ExecMainPID':
                            pid_info['pid'] = int(value) if value != '0' else None
        
        except Exception as e:
            self.logger.error(f"Erreur lors de l'obtention du PID pour {service_name}: {e}")
        
        return pid_info
    
    def _collect_failed_services(self) -> List[Dict[str, Any]]:
        """Collecte les services en échec"""
        failed_services = []
        
        try:
            # Utiliser systemctl pour les services en échec
            result = self.execute_command(['systemctl', 'list-units', '--type=service', '--state=failed'])
            
            if result['success']:
                lines = result['stdout'].split('\n')
                
                for line in lines:
                    if line.strip() and not line.startswith('UNIT'):
                        parts = line.split()
                        if len(parts) >= 4:
                            service_name = parts[0]
                            description = ' '.join(parts[4:]) if len(parts) > 4 else ''
                            
                            # Obtenir les logs d'erreur
                            error_logs = self._get_service_error_logs(service_name)
                            
                            failed_services.append({
                                'name': service_name,
                                'description': description,
                                'error_logs': error_logs
                            })
        
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte des services en échec: {e}")
        
        return failed_services
    
    def _get_service_error_logs(self, service_name: str) -> List[str]:
        """Obtient les logs d'erreur d'un service"""
        error_logs = []
        
        try:
            result = self.execute_command(['journalctl', '-u', service_name, '--no-pager', '-p', 'err', '-n', '5'])
            
            if result['success']:
                error_logs = result['stdout'].split('\n')[:5]
        
        except Exception as e:
            self.logger.error(f"Erreur lors de l'obtention des logs d'erreur pour {service_name}: {e}")
        
        return error_logs
    
    def _analyze_suspicious_services(self, results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyse les services suspects"""
        suspicious_services = []
        
        # Patterns de noms de services suspects
        suspicious_patterns = [
            r'\b(backdoor|trojan|malware|virus)\b',
            r'\b(keylogger|logger|spy)\b',
            r'\b(exploit|payload|shell)\b',
            r'\b(bot|botnet)\b',
            r'\b(miner|mining)\b',
            r'\b(stealer|spyware)\b',
            r'\b(rootkit|bootkit)\b'
        ]
        
        # Compiler les patterns
        compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in suspicious_patterns]
        
        # Analyser les services systemd
        for service_name, service_info in results.get('systemd_services', {}).items():
            suspicious_flags = []
            
            # Vérifier le nom du service
            for pattern in compiled_patterns:
                if pattern.search(service_name):
                    suspicious_flags.append(f"Nom suspect: {service_name}")
            
            # Vérifier la description
            description = service_info.get('description', '')
            for pattern in compiled_patterns:
                if pattern.search(description):
                    suspicious_flags.append(f"Description suspecte: {description}")
            
            # Vérifier les détails du service
            details = service_info.get('details', {})
            exec_start = details.get('ExecStart', '')
            if exec_start:
                for pattern in compiled_patterns:
                    if pattern.search(exec_start):
                        suspicious_flags.append(f"ExecStart suspect: {exec_start}")
            
            # Vérifier les services non standard
            if service_name not in self._get_standard_services():
                suspicious_flags.append("Service non standard")
            
            # Si des flags suspects sont trouvés
            if suspicious_flags:
                suspicious_services.append({
                    'service_name': service_name,
                    'service_type': 'systemd',
                    'service_info': service_info,
                    'suspicious_flags': suspicious_flags,
                    'risk_level': self._assess_service_risk(suspicious_flags)
                })
        
        # Analyser les services init.d
        for service_name, service_info in results.get('init_services', {}).items():
            suspicious_flags = []
            
            # Vérifier le nom du service
            for pattern in compiled_patterns:
                if pattern.search(service_name):
                    suspicious_flags.append(f"Nom suspect: {service_name}")
            
            # Vérifier le contenu du script
            content = service_info.get('content_preview', '')
            for pattern in compiled_patterns:
                if pattern.search(content):
                    suspicious_flags.append("Contenu du script suspect")
            
            # Si des flags suspects sont trouvés
            if suspicious_flags:
                suspicious_services.append({
                    'service_name': service_name,
                    'service_type': 'init.d',
                    'service_info': service_info,
                    'suspicious_flags': suspicious_flags,
                    'risk_level': self._assess_service_risk(suspicious_flags)
                })
        
        return suspicious_services
    
    def _get_standard_services(self) -> List[str]:
        """Retourne la liste des services standard"""
        return [
            'ssh', 'sshd', 'cron', 'rsyslog', 'systemd', 'dbus', 'network',
            'apache2', 'nginx', 'mysql', 'postgresql', 'docker', 'kubelet',
            'snapd', 'ufw', 'fail2ban', 'clamav', 'postfix', 'dovecot'
        ]
    
    def _assess_service_risk(self, flags: List[str]) -> str:
        """Évalue le niveau de risque d'un service"""
        high_risk_flags = [
            "Nom suspect:",
            "Description suspecte:",
            "ExecStart suspect:",
            "Contenu du script suspect"
        ]
        
        medium_risk_flags = [
            "Service non standard"
        ]
        
        if any(any(high_flag in flag for high_flag in high_risk_flags) for flag in flags):
            return 'high'
        elif any(any(medium_flag in flag for medium_flag in medium_risk_flags) for flag in flags):
            return 'medium'
        else:
            return 'low'
    
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Génère un résumé des services"""
        try:
            systemd_services = results.get('systemd_services', {})
            init_services = results.get('init_services', {})
            running_services = results.get('running_services', [])
            failed_services = results.get('failed_services', [])
            suspicious_services = results.get('suspicious_services', [])
            
            # Statistiques systemd
            systemd_stats = {
                'total_services': len(systemd_services),
                'running_services': len([s for s in systemd_services.values() if s.get('active_state') == 'active']),
                'failed_services': len([s for s in systemd_services.values() if s.get('active_state') == 'failed']),
                'enabled_services': len([s for s in systemd_services.values() if s.get('unit_file_state') == 'enabled'])
            }
            
            # Statistiques init.d
            init_stats = {
                'total_services': len(init_services),
                'running_services': len([s for s in init_services.values() if s.get('status') == 'running'])
            }
            
            # Statistiques des services suspects
            suspicious_stats = {
                'total_suspicious_services': len(suspicious_services),
                'high_risk_services': len([s for s in suspicious_services if s.get('risk_level') == 'high']),
                'medium_risk_services': len([s for s in suspicious_services if s.get('risk_level') == 'medium']),
                'low_risk_services': len([s for s in suspicious_services if s.get('risk_level') == 'low'])
            }
            
            return {
                'systemd_statistics': systemd_stats,
                'init_statistics': init_stats,
                'running_services_count': len(running_services),
                'failed_services_count': len(failed_services),
                'suspicious_services_statistics': suspicious_stats,
                'total_services_analyzed': len(systemd_services) + len(init_services)
            }
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la génération du résumé: {e}")
            return {'error': str(e)} 