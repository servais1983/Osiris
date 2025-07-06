"""
Collecteur pour les processus Linux
Collecte les informations sur les processus en cours d'exécution
"""

import os
import re
import psutil
from datetime import datetime
from typing import Dict, List, Any
from .base import LinuxCollector

class ProcessesCollector(LinuxCollector):
    """Collecteur pour les processus Linux (multi-OS safe)"""
    
    def __init__(self):
        super().__init__()
        self.psutil_available = self._check_psutil_availability()
    
    def _check_psutil_availability(self) -> bool:
        """Vérifie si psutil est disponible"""
        try:
            import psutil
            return True
        except ImportError:
            self.logger.warning("Module psutil non disponible sur ce système.")
            return False
    
    def collect(self) -> Dict[str, Any]:
        """Collecte les informations sur les processus"""
        results = {
            'system_info': self.get_system_info(),
            'processes': [],
            'process_tree': {},
            'suspicious_processes': [],
            'network_processes': [],
            'summary': {}
        }
        
        try:
            if self.psutil_available:
                # Utiliser psutil si disponible
                results['processes'] = self._collect_processes_psutil()
            else:
                # Fallback vers /proc si disponible
                if os.path.exists('/proc'):
                    results['processes'] = self._collect_processes_proc()
                else:
                    self.logger.warning("Aucune méthode de collecte de processus disponible sur ce système.")
            
            # Construire l'arbre des processus
            results['process_tree'] = self._build_process_tree(results['processes'])
            
            # Analyser les processus suspects
            results['suspicious_processes'] = self._analyze_suspicious_processes(results['processes'])
            
            # Collecter les processus avec des connexions réseau
            results['network_processes'] = self._collect_network_processes(results['processes'])
            
            # Générer un résumé
            results['summary'] = self._generate_summary(results)
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte des processus: {e}")
        
        return results
    
    def _collect_processes_psutil(self) -> List[Dict[str, Any]]:
        """Collecte les processus via psutil"""
        processes = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'cpu_percent', 'memory_percent', 'status', 'create_time']):
                try:
                    proc_info = proc.info
                    processes.append({
                        'pid': proc_info['pid'],
                        'name': proc_info['name'],
                        'cmdline': ' '.join(proc_info['cmdline']) if proc_info['cmdline'] else '',
                        'cpu_percent': proc_info['cpu_percent'],
                        'memory_percent': proc_info['memory_percent'],
                        'status': proc_info['status'],
                        'create_time': datetime.fromtimestamp(proc_info['create_time']).isoformat() if proc_info['create_time'] else None
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte via psutil: {e}")
        
        return processes
    
    def _collect_processes_proc(self) -> List[Dict[str, Any]]:
        """Collecte les processus via /proc (fallback)"""
        processes = []
        
        try:
            if not os.path.exists('/proc'):
                self.logger.warning("/proc non disponible sur ce système.")
                return processes
            
            for pid_dir in os.listdir('/proc'):
                if pid_dir.isdigit():
                    try:
                        proc_info = self._get_process_info_from_proc(pid_dir)
                        if proc_info:
                            processes.append(proc_info)
                    except Exception as e:
                        continue
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte via /proc: {e}")
        
        return processes
    
    def _collect_proc_info(self, pid: int) -> Dict[str, Any]:
        """Collecte les informations depuis /proc/[pid]"""
        proc_data = {}
        
        try:
            proc_path = f"/proc/{pid}"
            
            # /proc/[pid]/stat
            try:
                with open(f"{proc_path}/stat", 'r') as f:
                    stat_data = f.read().split()
                    if len(stat_data) >= 52:
                        proc_data['stat'] = {
                            'state': stat_data[2],
                            'ppid': int(stat_data[3]),
                            'pgrp': int(stat_data[4]),
                            'session': int(stat_data[5]),
                            'tty_nr': int(stat_data[6]),
                            'tpgid': int(stat_data[7]),
                            'flags': int(stat_data[8]),
                            'minflt': int(stat_data[9]),
                            'cminflt': int(stat_data[10]),
                            'majflt': int(stat_data[11]),
                            'cmajflt': int(stat_data[12]),
                            'utime': int(stat_data[13]),
                            'stime': int(stat_data[14]),
                            'cutime': int(stat_data[15]),
                            'cstime': int(stat_data[16]),
                            'priority': int(stat_data[17]),
                            'nice': int(stat_data[18]),
                            'num_threads': int(stat_data[19]),
                            'itrealvalue': int(stat_data[20]),
                            'starttime': int(stat_data[21]),
                            'vsize': int(stat_data[22]),
                            'rss': int(stat_data[23])
                        }
            except:
                pass
            
            # /proc/[pid]/status
            try:
                with open(f"{proc_path}/status", 'r') as f:
                    status_data = {}
                    for line in f:
                        if ':' in line:
                            key, value = line.split(':', 1)
                            status_data[key.strip()] = value.strip()
                    proc_data['status'] = status_data
            except:
                pass
            
            # /proc/[pid]/cmdline
            try:
                with open(f"{proc_path}/cmdline", 'r') as f:
                    cmdline = f.read().replace('\x00', ' ').strip()
                    proc_data['cmdline_raw'] = cmdline
            except:
                pass
            
            # /proc/[pid]/environ
            try:
                with open(f"{proc_path}/environ", 'r') as f:
                    environ_raw = f.read()
                    environ = {}
                    for item in environ_raw.split('\x00'):
                        if '=' in item:
                            key, value = item.split('=', 1)
                            environ[key] = value
                    proc_data['environ'] = environ
            except:
                pass
            
            # /proc/[pid]/fd
            try:
                fd_count = 0
                for fd in os.listdir(f"{proc_path}/fd"):
                    fd_count += 1
                proc_data['fd_count'] = fd_count
            except:
                pass
            
            # /proc/[pid]/maps
            try:
                with open(f"{proc_path}/maps", 'r') as f:
                    maps = []
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 5:
                            maps.append({
                                'address': parts[0],
                                'permissions': parts[1],
                                'offset': parts[2],
                                'device': parts[3],
                                'inode': parts[4],
                                'pathname': parts[5] if len(parts) > 5 else None
                            })
                    proc_data['memory_maps'] = maps
            except:
                pass
        
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte des informations /proc/{pid}: {e}")
        
        return proc_data
    
    def _build_process_tree(self, processes: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Construit l'arbre des processus"""
        tree = {}
        
        # Créer un dictionnaire par PID
        process_dict = {proc['pid']: proc for proc in processes}
        
        # Construire l'arbre
        for proc in processes:
            pid = proc['pid']
            ppid = proc['ppid']
            
            if ppid == 0:  # Processus racine
                tree[pid] = {
                    'process': proc,
                    'children': []
                }
            else:
                # Ajouter comme enfant du parent
                if ppid in process_dict:
                    if ppid not in tree:
                        tree[ppid] = {
                            'process': process_dict[ppid],
                            'children': []
                        }
                    tree[ppid]['children'].append({
                        'process': proc,
                        'children': []
                    })
        
        return tree
    
    def _analyze_suspicious_processes(self, processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyse les processus suspects"""
        suspicious_processes = []
        
        # Patterns de noms de processus suspects
        suspicious_names = [
            r'\b(nc|netcat|ncat)\b',
            r'\b(ssh|sshd)\b',
            r'\b(telnet|rsh|rlogin)\b',
            r'\b(backdoor|trojan|malware|virus)\b',
            r'\b(keylogger|logger)\b',
            r'\b(miner|mining)\b',
            r'\b(bot|botnet)\b',
            r'\b(shell|reverse)\b',
            r'\b(exploit|payload)\b',
            r'\b(stealer|spyware)\b'
        ]
        
        # Compiler les patterns
        compiled_patterns = [re.compile(pattern, re.IGNORECASE) for pattern in suspicious_names]
        
        for proc in processes:
            suspicious_flags = []
            
            # Vérifier le nom du processus
            proc_name = proc.get('name', '').lower()
            for pattern in compiled_patterns:
                if pattern.search(proc_name):
                    suspicious_flags.append(f"Nom suspect: {proc_name}")
            
            # Vérifier la ligne de commande
            cmdline = ' '.join(proc.get('cmdline', [])).lower()
            if any(pattern.search(cmdline) for pattern in compiled_patterns):
                suspicious_flags.append("Ligne de commande suspecte")
            
            # Vérifier les connexions réseau
            connections = proc.get('connections', [])
            if connections:
                for conn in connections:
                    if conn.get('raddr') and conn.get('raddr') not in ['127.0.0.1', 'localhost']:
                        suspicious_flags.append(f"Connexion réseau externe: {conn.get('raddr')}")
            
            # Vérifier les privilèges
            if proc.get('username') == 'root':
                suspicious_flags.append("Exécution en tant que root")
            
            # Vérifier les fichiers temporaires
            exe = proc.get('exe', '')
            if exe and any(path in exe.lower() for path in ['/tmp/', '/var/tmp/', '/dev/shm/']):
                suspicious_flags.append("Exécutable dans un répertoire temporaire")
            
            # Vérifier les processus orphelins
            if proc.get('ppid') == 1 and proc.get('username') != 'root':
                suspicious_flags.append("Processus orphelin (PPID = 1)")
            
            # Si des flags suspects sont trouvés
            if suspicious_flags:
                suspicious_processes.append({
                    'process': proc,
                    'suspicious_flags': suspicious_flags,
                    'risk_level': self._assess_process_risk(suspicious_flags)
                })
        
        return suspicious_processes
    
    def _assess_process_risk(self, flags: List[str]) -> str:
        """Évalue le niveau de risque d'un processus"""
        high_risk_flags = [
            "Nom suspect:",
            "Ligne de commande suspecte",
            "Exécutable dans un répertoire temporaire"
        ]
        
        medium_risk_flags = [
            "Connexion réseau externe:",
            "Exécution en tant que root",
            "Processus orphelin"
        ]
        
        if any(any(high_flag in flag for high_flag in high_risk_flags) for flag in flags):
            return 'high'
        elif any(any(medium_flag in flag for medium_flag in medium_risk_flags) for flag in flags):
            return 'medium'
        else:
            return 'low'
    
    def _collect_network_processes(self, processes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Collecte les processus avec des connexions réseau"""
        network_processes = []
        
        for proc in processes:
            connections = proc.get('connections', [])
            if connections:
                network_processes.append({
                    'process': proc,
                    'connections': connections,
                    'connection_count': len(connections),
                    'has_external_connections': any(
                        conn.get('raddr') and conn.get('raddr') not in ['127.0.0.1', 'localhost']
                        for conn in connections
                    )
                })
        
        # Trier par nombre de connexions
        network_processes.sort(key=lambda x: x['connection_count'], reverse=True)
        
        return network_processes
    
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Génère un résumé des processus"""
        try:
            processes = results.get('processes', [])
            suspicious = results.get('suspicious_processes', [])
            network = results.get('network_processes', [])
            
            # Statistiques par utilisateur
            user_stats = {}
            for proc in processes:
                username = proc.get('username', 'unknown')
                if username not in user_stats:
                    user_stats[username] = {
                        'process_count': 0,
                        'total_cpu': 0,
                        'total_memory': 0
                    }
                user_stats[username]['process_count'] += 1
                user_stats[username]['total_cpu'] += proc.get('cpu_percent', 0)
                user_stats[username]['total_memory'] += proc.get('memory_percent', 0)
            
            # Statistiques par statut
            status_stats = {}
            for proc in processes:
                status = proc.get('status', 'unknown')
                status_stats[status] = status_stats.get(status, 0) + 1
            
            return {
                'total_processes': len(processes),
                'suspicious_processes_count': len(suspicious),
                'network_processes_count': len(network),
                'high_risk_processes': len([p for p in suspicious if p.get('risk_level') == 'high']),
                'medium_risk_processes': len([p for p in suspicious if p.get('risk_level') == 'medium']),
                'low_risk_processes': len([p for p in suspicious if p.get('risk_level') == 'low']),
                'user_statistics': user_stats,
                'status_statistics': status_stats,
                'process_tree_depth': self._calculate_tree_depth(results.get('process_tree', {}))
            }
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la génération du résumé: {e}")
            return {'error': str(e)}
    
    def _calculate_tree_depth(self, tree: Dict[str, Any], current_depth: int = 0) -> int:
        """Calcule la profondeur de l'arbre des processus"""
        if not tree:
            return current_depth
        
        max_depth = current_depth
        for pid, node in tree.items():
            children_depth = self._calculate_tree_depth(
                {child['process']['pid']: child for child in node.get('children', [])},
                current_depth + 1
            )
            max_depth = max(max_depth, children_depth)
        
        return max_depth 