"""
Collecteur pour les services systemd Linux
Collecte les informations détaillées sur les services systemd
"""

import os
import re
import subprocess
from datetime import datetime
from typing import Dict, List, Any
from .base import LinuxCollector

class SystemdServicesCollector(LinuxCollector):
    """Collecteur pour les services systemd (multi-OS safe)"""
    
    def __init__(self):
        super().__init__()
        self.systemctl_available = self._check_systemctl_availability()
    
    def _check_systemctl_availability(self) -> bool:
        """Vérifie si systemctl est disponible"""
        try:
            result = subprocess.run(['systemctl', '--version'], 
                                  capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            self.logger.warning("systemctl non disponible sur ce système.")
            return False
    
    def collect(self) -> Dict[str, Any]:
        """Collecte les informations sur les services systemd"""
        results = {
            'system_info': self.get_system_info(),
            'services': {},
            'running_services': [],
            'failed_services': [],
            'enabled_services': [],
            'disabled_services': [],
            'suspicious_services': [],
            'service_dependencies': {},
            'summary': {}
        }
        
        try:
            if self.systemctl_available:
                # Collecter les services systemd
                results['services'] = self._collect_systemd_services()
                results['running_services'] = self._collect_running_services()
                results['failed_services'] = self._collect_failed_services()
                results['enabled_services'] = self._collect_enabled_services()
                results['disabled_services'] = self._collect_disabled_services()
                
                # Analyser les services suspects
                results['suspicious_services'] = self._analyze_suspicious_services(results['services'])
                
                # Collecter les dépendances
                results['service_dependencies'] = self._collect_service_dependencies()
            else:
                self.logger.warning("systemd non disponible sur ce système.")
            
            # Générer un résumé
            results['summary'] = self._generate_summary(results)
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte des services: {e}")
        
        return results
    
    def _collect_systemd_services(self) -> Dict[str, Dict[str, Any]]:
        """Collecte tous les services systemd"""
        services = {}
        
        try:
            if not self.systemctl_available:
                return services
            
            # Lister tous les services
            result = self.execute_command(['systemctl', 'list-units', '--type=service', '--all'])
            
            if result['success']:
                lines = result['stdout'].split('\n')
                
                for line in lines[1:]:  # Ignorer l'en-tête
                    if line.strip():
                        service_info = self._parse_service_line(line)
                        if service_info:
                            services[service_info['name']] = service_info
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte des services systemd: {e}")
        
        return services
    
    def _get_service_details(self, service_name: str) -> Dict[str, Any]:
        """Obtient les détails d'un service"""
        details = {}
        
        try:
            # Obtenir les propriétés du service
            result = self.execute_command(['systemctl', 'show', service_name, '--no-pager'])
            
            if result['success']:
                for line in result['stdout'].split('\n'):
                    if '=' in line:
                        key, value = line.split('=', 1)
                        details[key.strip()] = value.strip()
            
            # Obtenir le statut détaillé
            result = self.execute_command(['systemctl', 'status', service_name, '--no-pager'])
            
            if result['success']:
                details['status_output'] = result['stdout']
                
                # Extraire le PID principal
                pid_match = re.search(r'Main PID: (\d+)', result['stdout'])
                if pid_match:
                    details['main_pid'] = int(pid_match.group(1))
                
                # Extraire l'utilisation mémoire
                memory_match = re.search(r'Memory: ([0-9.]+ [KMGT]?B)', result['stdout'])
                if memory_match:
                    details['memory_usage'] = memory_match.group(1)
                
                # Extraire l'utilisation CPU
                cpu_match = re.search(r'CPU: ([0-9.]+)s', result['stdout'])
                if cpu_match:
                    details['cpu_usage'] = cpu_match.group(1)
            
            # Obtenir les logs récents
            result = self.execute_command(['journalctl', '-u', service_name, '--no-pager', '-n', '5'])
            
            if result['success']:
                details['recent_logs'] = result['stdout'].split('\n')[:5]
            
            # Obtenir les connexions réseau du service
            if 'main_pid' in details:
                network_info = self._get_service_network_info(details['main_pid'])
                if network_info:
                    details['network_connections'] = network_info
        
        except Exception as e:
            self.logger.error(f"Erreur lors de l'obtention des détails pour {service_name}: {e}")
        
        return details
    
    def _get_service_network_info(self, pid: int) -> List[Dict[str, Any]]:
        """Obtient les informations réseau d'un service"""
        network_info = []
        
        try:
            result = self.execute_command(['ss', '-p', '--numeric', '--processes'])
            
            if result['success']:
                lines = result['stdout'].split('\n')
                
                for line in lines:
                    if str(pid) in line:
                        # Parse: tcp    ESTAB 0      0      192.168.1.100:22      192.168.1.1:12345    users:(("sshd",pid=1234,fd=3))
                        parts = line.split()
                        if len(parts) >= 4:
                            connection = {
                                'protocol': parts[0],
                                'state': parts[1],
                                'local_address': parts[4] if len(parts) > 4 else '',
                                'peer_address': parts[5] if len(parts) > 5 else '',
                                'process_info': parts[-1] if parts[-1].startswith('users:') else ''
                            }
                            network_info.append(connection)
        
        except Exception as e:
            self.logger.error(f"Erreur lors de l'obtention des informations réseau pour PID {pid}: {e}")
        
        return network_info
    
    def _get_running_services(self, services: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Obtient les services en cours d'exécution"""
        running_services = []
        
        for service_name, service_info in services.items():
            if service_info.get('active_state') == 'active':
                running_services.append({
                    'name': service_name,
                    'info': service_info
                })
        
        return running_services
    
    def _get_failed_services(self, services: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Obtient les services en échec"""
        failed_services = []
        
        for service_name, service_info in services.items():
            if service_info.get('active_state') == 'failed':
                failed_services.append({
                    'name': service_name,
                    'info': service_info
                })
        
        return failed_services
    
    def _get_enabled_services(self, services: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Obtient les services activés"""
        enabled_services = []
        
        for service_name, service_info in services.items():
            if service_info.get('unit_file_state') == 'enabled':
                enabled_services.append({
                    'name': service_name,
                    'info': service_info
                })
        
        return enabled_services
    
    def _get_disabled_services(self, services: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Obtient les services désactivés"""
        disabled_services = []
        
        for service_name, service_info in services.items():
            if service_info.get('unit_file_state') == 'disabled':
                disabled_services.append({
                    'name': service_name,
                    'info': service_info
                })
        
        return disabled_services
    
    def _analyze_suspicious_services(self, services: Dict[str, Any]) -> List[Dict[str, Any]]:
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
        
        for service_name, service_info in services.items():
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
            
            # Vérifier ExecStart
            exec_start = details.get('ExecStart', '')
            if exec_start:
                for pattern in compiled_patterns:
                    if pattern.search(exec_start):
                        suspicious_flags.append(f"ExecStart suspect: {exec_start}")
            
            # Vérifier WorkingDirectory
            working_dir = details.get('WorkingDirectory', '')
            if working_dir in ['/tmp', '/var/tmp', '/dev/shm']:
                suspicious_flags.append(f"Répertoire de travail suspect: {working_dir}")
            
            # Vérifier User
            user = details.get('User', '')
            if user == 'root' and not self._is_standard_root_service(service_name):
                suspicious_flags.append("Exécution en tant que root")
            
            # Vérifier les services non standard
            if not self._is_standard_service(service_name):
                suspicious_flags.append("Service non standard")
            
            # Vérifier les connexions réseau suspectes
            network_connections = details.get('network_connections', [])
            for conn in network_connections:
                if conn.get('peer_address') and conn.get('peer_address') not in ['127.0.0.1', 'localhost']:
                    suspicious_flags.append(f"Connexion réseau externe: {conn.get('peer_address')}")
            
            # Si des flags suspects sont trouvés
            if suspicious_flags:
                suspicious_services.append({
                    'service_name': service_name,
                    'service_info': service_info,
                    'suspicious_flags': suspicious_flags,
                    'risk_level': self._assess_service_risk(suspicious_flags)
                })
        
        return suspicious_services
    
    def _is_standard_service(self, service_name: str) -> bool:
        """Vérifie si un service est standard"""
        standard_services = [
            'ssh', 'sshd', 'cron', 'rsyslog', 'systemd', 'dbus', 'network',
            'apache2', 'nginx', 'mysql', 'postgresql', 'docker', 'kubelet',
            'snapd', 'ufw', 'fail2ban', 'clamav', 'postfix', 'dovecot',
            'cups', 'avahi-daemon', 'bluetooth', 'wpa_supplicant', 'NetworkManager'
        ]
        
        return any(service_name.startswith(service) for service in standard_services)
    
    def _is_standard_root_service(self, service_name: str) -> bool:
        """Vérifie si un service root est standard"""
        standard_root_services = [
            'ssh', 'sshd', 'systemd', 'dbus', 'network', 'ufw', 'fail2ban',
            'cups', 'avahi-daemon', 'bluetooth', 'wpa_supplicant', 'NetworkManager'
        ]
        
        return any(service_name.startswith(service) for service in standard_root_services)
    
    def _assess_service_risk(self, flags: List[str]) -> str:
        """Évalue le niveau de risque d'un service"""
        high_risk_flags = [
            "Nom suspect:",
            "Description suspecte:",
            "ExecStart suspect:",
            "Répertoire de travail suspect:"
        ]
        
        medium_risk_flags = [
            "Exécution en tant que root",
            "Service non standard",
            "Connexion réseau externe:"
        ]
        
        if any(any(high_flag in flag for high_flag in high_risk_flags) for flag in flags):
            return 'high'
        elif any(any(medium_flag in flag for medium_flag in medium_risk_flags) for flag in flags):
            return 'medium'
        else:
            return 'low'
    
    def _analyze_service_dependencies(self, services: Dict[str, Any]) -> Dict[str, Any]:
        """Analyse les dépendances entre services"""
        dependencies = {
            'service_dependencies': {},
            'reverse_dependencies': {},
            'dependency_graph': {}
        }
        
        try:
            for service_name in services.keys():
                # Obtenir les dépendances d'un service
                result = self.execute_command(['systemctl', 'list-dependencies', service_name, '--no-pager'])
                
                if result['success']:
                    deps = []
                    lines = result['stdout'].split('\n')
                    
                    for line in lines:
                        line = line.strip()
                        if line and not line.startswith(service_name) and not line.startswith('●'):
                            # Nettoyer le nom du service
                            dep_name = line.replace('●', '').replace('○', '').strip()
                            if dep_name:
                                deps.append(dep_name)
                    
                    dependencies['service_dependencies'][service_name] = deps
                    
                    # Construire les dépendances inverses
                    for dep in deps:
                        if dep not in dependencies['reverse_dependencies']:
                            dependencies['reverse_dependencies'][dep] = []
                        dependencies['reverse_dependencies'][dep].append(service_name)
        
        except Exception as e:
            self.logger.error(f"Erreur lors de l'analyse des dépendances: {e}")
        
        return dependencies
    
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Génère un résumé des services systemd"""
        try:
            services = results.get('services', {})
            running_services = results.get('running_services', [])
            failed_services = results.get('failed_services', [])
            enabled_services = results.get('enabled_services', [])
            disabled_services = results.get('disabled_services', [])
            suspicious_services = results.get('suspicious_services', [])
            
            # Statistiques générales
            general_stats = {
                'total_services': len(services),
                'running_services': len(running_services),
                'failed_services': len(failed_services),
                'enabled_services': len(enabled_services),
                'disabled_services': len(disabled_services)
            }
            
            # Statistiques des services suspects
            suspicious_stats = {
                'total_suspicious_services': len(suspicious_services),
                'high_risk_services': len([s for s in suspicious_services if s.get('risk_level') == 'high']),
                'medium_risk_services': len([s for s in suspicious_services if s.get('risk_level') == 'medium']),
                'low_risk_services': len([s for s in suspicious_services if s.get('risk_level') == 'low'])
            }
            
            # Statistiques des états de chargement
            load_states = {}
            for service_info in services.values():
                load_state = service_info.get('load_state', 'unknown')
                load_states[load_state] = load_states.get(load_state, 0) + 1
            
            # Statistiques des états actifs
            active_states = {}
            for service_info in services.values():
                active_state = service_info.get('active_state', 'unknown')
                active_states[active_state] = active_states.get(active_state, 0) + 1
            
            return {
                'general_statistics': general_stats,
                'suspicious_services_statistics': suspicious_stats,
                'load_state_statistics': load_states,
                'active_state_statistics': active_states,
                'dependency_statistics': {
                    'services_with_dependencies': len(results.get('service_dependencies', {}).get('service_dependencies', {})),
                    'total_dependencies': sum(len(deps) for deps in results.get('service_dependencies', {}).get('service_dependencies', {}).values())
                }
            }
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la génération du résumé: {e}")
            return {'error': str(e)} 