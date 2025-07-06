from typing import Dict, List, Any, Optional
from datetime import datetime
import psutil
import win32process
import win32api
import win32security
import win32con
import win32ts
import win32net
import win32netcon
import win32profile
import win32cred
import win32security
import win32file
import win32timezone
import win32evtlog
import win32evtlogutil
import win32gui
import win32ui
import win32print
import win32com.client
import pythoncom
import yara
import hashlib
import os
from pathlib import Path
from .base import WindowsCollector
import re

class ProcessesCollector(WindowsCollector):
    """Collecteur pour les processus Windows (multi-OS safe)"""
    
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
        # Utilise la gestion d'erreur de la base
        return super().collect()

    def _collect(self) -> Dict[str, Any]:
        results = {
            'system_info': self.get_system_info(),
            'processes': [],
            'suspicious_processes': [],
            'network_processes': [],
            'process_tree': {},
            'summary': {}
        }
        
        try:
            if self.psutil_available:
                # Utiliser psutil si disponible
                results['processes'] = self._collect_processes_psutil()
            else:
                self.logger.warning("Aucune méthode de collecte de processus disponible sur ce système.")
            
            # Analyser les processus suspects
            results['suspicious_processes'] = self._analyze_suspicious_processes(results['processes'])
            
            # Collecter les processus avec des connexions réseau
            results['network_processes'] = self._collect_network_processes(results['processes'])
            
            # Construire l'arbre des processus
            results['process_tree'] = self._build_process_tree(results['processes'])
            
            # Générer un résumé
            results['summary'] = self._generate_summary(results)
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte des processus: {e}")
            results['error'] = str(e)
        
        return results
    
    def _collect_processes_psutil(self) -> List[Dict[str, Any]]:
        """Collecte les processus via psutil"""
        processes = []
        
        try:
            for proc in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'create_time', 
                                           'cpu_percent', 'memory_percent', 'status', 'username',
                                           'ppid', 'num_threads']):
                try:
                    proc_info = proc.info
                    
                    # Informations de base
                    process_data = {
                        'pid': proc_info['pid'],
                        'name': proc_info['name'],
                        'exe': proc_info['exe'],
                        'cmdline': proc_info['cmdline'],
                        'create_time': datetime.fromtimestamp(proc_info['create_time']).isoformat() if proc_info['create_time'] else None,
                        'cpu_percent': proc_info['cpu_percent'],
                        'memory_percent': proc_info['memory_percent'],
                        'status': proc_info['status'],
                        'username': proc_info['username'],
                        'ppid': proc_info['ppid'],
                        'num_threads': proc_info['num_threads'],
                        'connections': []
                    }
                    
                    # Collecter les connexions réseau si Windows API disponible
                    if self._windows_available():
                        try:
                            connections = proc.connections()
                            for conn in connections:
                                process_data['connections'].append({
                                    'family': str(conn.family),
                                    'type': str(conn.type),
                                    'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                                    'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                                    'status': conn.status
                                })
                        except (psutil.AccessDenied, psutil.NoSuchProcess):
                            pass
                    
                    # Collecter les informations du fichier exécutable
                    if proc_info['exe']:
                        process_data['file_info'] = self.get_file_info(proc_info['exe'])
                    
                    processes.append(process_data)
                    
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
                    
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte via psutil: {e}")
        
        return processes
    
    def _get_process_info(self, proc: psutil.Process) -> Optional[Dict[str, Any]]:
        """Récupère les informations détaillées d'un processus"""
        try:
            # Informations de base
            info = {
                'pid': proc.pid,
                'name': proc.name(),
                'username': proc.username(),
                'create_time': datetime.fromtimestamp(proc.create_time()),
                'cpu_percent': proc.cpu_percent(),
                'memory_percent': proc.memory_percent(),
                'status': proc.status()
            }
            
            # Informations mémoire
            mem_info = proc.memory_info()
            info['memory'] = {
                'rss': mem_info.rss,  # Resident Set Size
                'vms': mem_info.vms,  # Virtual Memory Size
                'shared': mem_info.shared,
                'text': mem_info.text,
                'lib': mem_info.lib,
                'data': mem_info.data,
                'dirty': mem_info.dirty
            }
            
            # Informations CPU
            info['cpu'] = {
                'num_threads': proc.num_threads(),
                'cpu_times': {
                    'user': proc.cpu_times().user,
                    'system': proc.cpu_times().system,
                    'children_user': proc.cpu_times().children_user,
                    'children_system': proc.cpu_times().children_system
                }
            }
            
            # Informations I/O
            try:
                io_counters = proc.io_counters()
                info['io'] = {
                    'read_bytes': io_counters.read_bytes,
                    'write_bytes': io_counters.write_bytes,
                    'read_count': io_counters.read_count,
                    'write_count': io_counters.write_count
                }
            except:
                info['io'] = None
            
            # Informations réseau
            try:
                connections = proc.connections()
                info['network'] = [{
                    'fd': conn.fd,
                    'family': conn.family,
                    'type': conn.type,
                    'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status
                } for conn in connections]
            except:
                info['network'] = []
            
            # Informations sur les fichiers ouverts
            try:
                open_files = proc.open_files()
                info['open_files'] = [{
                    'path': f.path,
                    'fd': f.fd
                } for f in open_files]
            except:
                info['open_files'] = []
            
            # Informations sur les threads
            try:
                threads = proc.threads()
                info['threads'] = [{
                    'id': t.id,
                    'user_time': t.user_time,
                    'system_time': t.system_time
                } for t in threads]
            except:
                info['threads'] = []
            
            # Informations sur les handles
            try:
                handles = self._get_process_handles(proc.pid)
                info['handles'] = handles
            except:
                info['handles'] = []
            
            # Informations sur les modules chargés
            try:
                modules = self._get_process_modules(proc.pid)
                info['modules'] = modules
            except:
                info['modules'] = []
            
            # Informations sur les variables d'environnement
            try:
                env = proc.environ()
                info['environment'] = env
            except:
                info['environment'] = {}
            
            # Informations sur la ligne de commande
            try:
                cmdline = proc.cmdline()
                info['cmdline'] = cmdline
            except:
                info['cmdline'] = []
            
            # Informations sur le chemin d'exécution
            try:
                exe = proc.exe()
                info['exe'] = exe
                
                # Calcul du hash du fichier
                if os.path.exists(exe):
                    info['exe_hash'] = self._calculate_file_hash(exe)
            except:
                info['exe'] = None
                info['exe_hash'] = None
            
            # Informations sur le répertoire de travail
            try:
                cwd = proc.cwd()
                info['cwd'] = cwd
            except:
                info['cwd'] = None
            
            # Informations sur les privilèges
            try:
                privileges = self._get_process_privileges(proc.pid)
                info['privileges'] = privileges
            except:
                info['privileges'] = []
            
            # Informations sur les tokens
            try:
                tokens = self._get_process_tokens(proc.pid)
                info['tokens'] = tokens
            except:
                info['tokens'] = []
            
            return info
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des informations du processus {proc.pid}: {e}")
            return None
    
    def _get_process_handles(self, pid: int) -> List[Dict[str, Any]]:
        """Récupère les handles d'un processus"""
        handles = []
        
        try:
            # Ouverture du processus
            process_handle = win32api.OpenProcess(
                win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ,
                False,
                pid
            )
            
            # Récupération des handles
            handle_info = win32process.GetProcessHandleCount(process_handle)
            
            # Fermeture du handle
            win32api.CloseHandle(process_handle)
            
            return [{
                'count': handle_info,
                'pid': pid
            }]
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des handles du processus {pid}: {e}")
            return []
    
    def _get_process_modules(self, pid: int) -> List[Dict[str, Any]]:
        """Récupère les modules chargés par un processus"""
        modules = []
        
        try:
            # Ouverture du processus
            process_handle = win32api.OpenProcess(
                win32con.PROCESS_QUERY_INFORMATION | win32con.PROCESS_VM_READ,
                False,
                pid
            )
            
            # Récupération des modules
            module_list = win32process.EnumProcessModules(process_handle)
            
            for module in module_list:
                try:
                    module_info = win32process.GetModuleFileNameEx(process_handle, module)
                    module_name = win32process.GetModuleBaseName(process_handle, module)
                    
                    modules.append({
                        'name': module_name,
                        'path': module_info,
                        'base_address': module
                    })
                except:
                    continue
            
            # Fermeture du handle
            win32api.CloseHandle(process_handle)
            
            return modules
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des modules du processus {pid}: {e}")
            return []
    
    def _get_process_privileges(self, pid: int) -> List[Dict[str, Any]]:
        """Récupère les privilèges d'un processus"""
        privileges = []
        
        try:
            # Ouverture du processus
            process_handle = win32api.OpenProcess(
                win32con.PROCESS_QUERY_INFORMATION,
                False,
                pid
            )
            
            # Ouverture du token
            token_handle = win32security.OpenProcessToken(
                process_handle,
                win32con.TOKEN_QUERY
            )
            
            # Récupération des privilèges
            privs = win32security.GetTokenInformation(
                token_handle,
                win32security.TokenPrivileges
            )
            
            for priv in privs:
                try:
                    priv_name = win32security.LookupPrivilegeName(None, priv[0])
                    privileges.append({
                        'name': priv_name,
                        'enabled': bool(priv[1] & win32con.SE_PRIVILEGE_ENABLED)
                    })
                except:
                    continue
            
            # Fermeture des handles
            win32api.CloseHandle(token_handle)
            win32api.CloseHandle(process_handle)
            
            return privileges
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des privilèges du processus {pid}: {e}")
            return []
    
    def _get_process_tokens(self, pid: int) -> List[Dict[str, Any]]:
        """Récupère les tokens d'un processus"""
        tokens = []
        
        try:
            # Ouverture du processus
            process_handle = win32api.OpenProcess(
                win32con.PROCESS_QUERY_INFORMATION,
                False,
                pid
            )
            
            # Ouverture du token
            token_handle = win32security.OpenProcessToken(
                process_handle,
                win32con.TOKEN_QUERY
            )
            
            # Récupération des informations du token
            token_info = win32security.GetTokenInformation(
                token_handle,
                win32security.TokenUser
            )
            
            # Récupération du SID
            sid = win32security.ConvertSidToStringSid(token_info[0])
            
            # Récupération du nom d'utilisateur
            try:
                username = win32security.LookupAccountSid(None, token_info[0])[0]
            except:
                username = None
            
            tokens.append({
                'sid': sid,
                'username': username
            })
            
            # Fermeture des handles
            win32api.CloseHandle(token_handle)
            win32api.CloseHandle(process_handle)
            
            return tokens
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des tokens du processus {pid}: {e}")
            return []
    
    def _calculate_file_hash(self, file_path: str) -> Dict[str, str]:
        """Calcule les hashes d'un fichier"""
        hashes = {}
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
                # MD5
                hashes['md5'] = hashlib.md5(data).hexdigest()
                
                # SHA1
                hashes['sha1'] = hashlib.sha1(data).hexdigest()
                
                # SHA256
                hashes['sha256'] = hashlib.sha256(data).hexdigest()
                
            return hashes
            
        except Exception as e:
            self.logger.error(f"Erreur lors du calcul des hashes du fichier {file_path}: {e}")
            return {}
    
    def _get_system_info(self) -> Dict[str, Any]:
        """Récupère les informations système"""
        try:
            return {
                'cpu': {
                    'physical_cores': psutil.cpu_count(logical=False),
                    'total_cores': psutil.cpu_count(logical=True),
                    'max_frequency': psutil.cpu_freq().max if psutil.cpu_freq() else None,
                    'min_frequency': psutil.cpu_freq().min if psutil.cpu_freq() else None,
                    'current_frequency': psutil.cpu_freq().current if psutil.cpu_freq() else None,
                    'cpu_usage_per_core': [x for x in psutil.cpu_percent(percpu=True, interval=1)],
                    'total_cpu_usage': psutil.cpu_percent()
                },
                'memory': {
                    'total': psutil.virtual_memory().total,
                    'available': psutil.virtual_memory().available,
                    'used': psutil.virtual_memory().used,
                    'percentage': psutil.virtual_memory().percent,
                    'swap': {
                        'total': psutil.swap_memory().total,
                        'used': psutil.swap_memory().used,
                        'free': psutil.swap_memory().free,
                        'percentage': psutil.swap_memory().percent
                    }
                },
                'disk': {
                    'partitions': [{
                        'device': partition.device,
                        'mountpoint': partition.mountpoint,
                        'fstype': partition.fstype,
                        'opts': partition.opts
                    } for partition in psutil.disk_partitions()],
                    'usage': {
                        'total': psutil.disk_usage('/').total,
                        'used': psutil.disk_usage('/').used,
                        'free': psutil.disk_usage('/').free,
                        'percentage': psutil.disk_usage('/').percent
                    }
                },
                'network': {
                    'interfaces': psutil.net_if_addrs(),
                    'stats': psutil.net_if_stats(),
                    'connections': [{
                        'fd': conn.fd,
                        'family': conn.family,
                        'type': conn.type,
                        'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status
                    } for conn in psutil.net_connections()]
                },
                'sensors': {
                    'temperatures': psutil.sensors_temperatures(),
                    'fans': psutil.sensors_fans(),
                    'battery': psutil.sensors_battery()._asdict() if psutil.sensors_battery() else None
                },
                'boot_time': datetime.fromtimestamp(psutil.boot_time()).isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des informations système: {e}")
            return {} 