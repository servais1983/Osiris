#!/usr/bin/env python3
"""
Osiris - Collecteur Forensique Multi-OS
Script principal pour la collecte d'artefacts forensiques
"""

import sys
import json
import argparse
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('osiris.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def setup_argparse() -> argparse.ArgumentParser:
    """Configure l'analyseur d'arguments"""
    parser = argparse.ArgumentParser(
        description="Osiris - Collecteur Forensique Multi-OS",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemples d'utilisation:
  python osiris.py --collect users --output scan.json
  python osiris.py --collect-all --output full_scan.json
  python osiris.py --list
  python osiris.py --system-info
        """
    )
    
    parser.add_argument(
        '--collect', '-c',
        type=str,
        help='Nom du collecteur à exécuter (ex: users, processes, services)'
    )
    
    parser.add_argument(
        '--collect-all', '-a',
        action='store_true',
        help='Exécuter tous les collecteurs disponibles'
    )
    
    parser.add_argument(
        '--list', '-l',
        action='store_true',
        help='Lister tous les collecteurs disponibles'
    )
    
    parser.add_argument(
        '--system-info', '-s',
        action='store_true',
        help='Afficher les informations système'
    )
    
    parser.add_argument(
        '--platform', '-p',
        type=str,
        choices=['auto', 'windows', 'linux', 'macos'],
        default='auto',
        help='Plateforme cible (défaut: auto-détection)'
    )
    
    parser.add_argument(
        '--output', '-o',
        type=str,
        help='Fichier de sortie JSON'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Mode verbeux'
    )
    
    parser.add_argument(
        '--quiet', '-q',
        action='store_true',
        help='Mode silencieux (erreurs uniquement)'
    )
    
    return parser

def get_system_info() -> Dict[str, Any]:
    """Récupère les informations système"""
    import platform
    import os
    
    info = {
        'platform': platform.system().lower(),
        'platform_version': platform.version(),
        'hostname': platform.node(),
        'current_user': os.getenv('USERNAME') or os.getenv('USER'),
        'python_version': platform.python_version(),
        'timestamp': datetime.now().isoformat()
    }
    
    # Détection des privilèges admin
    try:
        if platform.system() == 'Windows':
            import ctypes
            info['is_admin'] = ctypes.windll.shell32.IsUserAnAdmin()
        else:
            info['is_admin'] = os.geteuid() == 0
    except:
        info['is_admin'] = False
    
    return info

def list_available_collectors() -> Dict[str, List[str]]:
    """Liste les collecteurs disponibles par plateforme"""
    collectors = {
        'windows': [
            'users', 'processes', 'services', 'network', 
            'files', 'registry', 'events', 'browser_history'
        ],
        'linux': [
            'users', 'processes', 'services', 'network',
            'files', 'system_logs', 'shell_history', 'cron_jobs'
        ],
        'macos': [
            'users', 'processes', 'services', 'network',
            'files', 'unified_logs', 'persistence'
        ]
    }
    
    # Filtrer selon la plateforme actuelle
    current_platform = get_system_info()['platform']
    if current_platform == 'windows':
        return {'windows': collectors['windows']}
    elif current_platform == 'linux':
        return {'linux': collectors['linux']}
    elif current_platform == 'darwin':
        return {'macos': collectors['macos']}
    else:
        return collectors

def collect_users() -> Dict[str, Any]:
    """Collecteur d'utilisateurs robuste"""
    results = {
        'system_info': get_system_info(),
        'data': {
            'users': [],
            'groups': [],
            'sessions': []
        },
        'summary': {
            'total_users': 0,
            'total_groups': 0,
            'total_sessions': 0,
            'timestamp': datetime.now().isoformat(),
            'mode': 'full'
        },
        'error': None
    }
    
    try:
        import platform
        current_platform = platform.system()
        
        if current_platform == 'Windows':
            results = _collect_windows_users()
        elif current_platform == 'Linux':
            results = _collect_linux_users()
        elif current_platform == 'Darwin':
            results = _collect_macos_users()
        else:
            results['error'] = f"Plateforme non supportée: {current_platform}"
            
    except Exception as e:
        results['error'] = str(e)
        results['summary']['mode'] = 'degraded'
    
    return results

def _collect_windows_users() -> Dict[str, Any]:
    """Collecte les utilisateurs Windows"""
    results = {
        'system_info': get_system_info(),
        'data': {'users': [], 'groups': [], 'sessions': []},
        'summary': {'total_users': 0, 'total_groups': 0, 'total_sessions': 0},
        'error': None
    }
    
    try:
        import subprocess
        import os
        
        # Collecte des utilisateurs via net user
        try:
            output = subprocess.check_output(['net', 'user'], text=True, shell=True)
            users = []
            for line in output.split('\n'):
                line = line.strip()
                if line and not line.startswith('La commande') and not line.startswith('Les commandes'):
                    # Nettoyer la sortie
                    if '\\' in line:
                        username = line.split('\\')[-1].strip()
                    else:
                        username = line
                    if username and len(username) > 1:
                        users.append(username)
            
            results['data']['users'] = users
            results['summary']['total_users'] = len(users)
        except Exception as e:
            logger.warning(f"Erreur collecte utilisateurs: {e}")
        
        # Collecte des groupes via net localgroup
        try:
            output = subprocess.check_output(['net', 'localgroup'], text=True, shell=True)
            groups = []
            for line in output.split('\n'):
                line = line.strip()
                if line and not line.startswith('La commande') and not line.startswith('Les commandes'):
                    if '\\' in line:
                        groupname = line.split('\\')[-1].strip()
                    else:
                        groupname = line
                    if groupname and len(groupname) > 1:
                        groups.append(groupname)
            
            results['data']['groups'] = groups
            results['summary']['total_groups'] = len(groups)
        except Exception as e:
            logger.warning(f"Erreur collecte groupes: {e}")
        
        # Collecte des sessions via quser
        try:
            output = subprocess.check_output(['quser'], text=True, shell=True)
            sessions = []
            for line in output.split('\n'):
                line = line.strip()
                if line and not line.startswith('USERNAME') and not line.startswith('La commande'):
                    sessions.append(line)
            
            results['data']['sessions'] = sessions
            results['summary']['total_sessions'] = len(sessions)
        except Exception as e:
            logger.warning(f"Erreur collecte sessions: {e}")
        
        # Collecte alternative via WMI si disponible
        if not results['data']['users']:
            try:
                import wmi
                c = wmi.WMI()
                users = []
                for user in c.Win32_UserAccount():
                    users.append({
                        'name': user.Name,
                        'domain': user.Domain,
                        'disabled': user.Disabled,
                        'lockout': user.Lockout
                    })
                results['data']['users'] = users
                results['summary']['total_users'] = len(users)
            except ImportError:
                pass
            except Exception as e:
                logger.warning(f"Erreur WMI: {e}")
        
        results['summary']['timestamp'] = datetime.now().isoformat()
        results['summary']['mode'] = 'full'
        
    except Exception as e:
        results['error'] = str(e)
        results['summary']['mode'] = 'degraded'
    
    return results

def _collect_linux_users() -> Dict[str, Any]:
    """Collecte les utilisateurs Linux"""
    results = {
        'system_info': get_system_info(),
        'data': {'users': [], 'groups': [], 'sessions': []},
        'summary': {'total_users': 0, 'total_groups': 0, 'total_sessions': 0},
        'error': None
    }
    
    try:
        import subprocess
        
        # Collecte des utilisateurs via /etc/passwd
        try:
            with open('/etc/passwd', 'r') as f:
                users = []
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        parts = line.split(':')
                        if len(parts) >= 3:
                            users.append({
                                'username': parts[0],
                                'uid': parts[2],
                                'gid': parts[3],
                                'home': parts[5],
                                'shell': parts[6]
                            })
            
            results['data']['users'] = users
            results['summary']['total_users'] = len(users)
        except:
            pass
        
        # Collecte des groupes via /etc/group
        try:
            with open('/etc/group', 'r') as f:
                groups = []
                for line in f:
                    if line.strip() and not line.startswith('#'):
                        parts = line.split(':')
                        if len(parts) >= 3:
                            groups.append({
                                'groupname': parts[0],
                                'gid': parts[2],
                                'members': parts[3].split(',') if len(parts) > 3 else []
                            })
            
            results['data']['groups'] = groups
            results['summary']['total_groups'] = len(groups)
        except:
            pass
        
        # Collecte des sessions via who
        try:
            output = subprocess.check_output(['who'], text=True, capture_output=True)
            sessions = []
            for line in output.split('\n'):
                if line.strip():
                    sessions.append(line.strip())
            
            results['data']['sessions'] = sessions
            results['summary']['total_sessions'] = len(sessions)
        except:
            pass
        
        results['summary']['timestamp'] = datetime.now().isoformat()
        results['summary']['mode'] = 'full'
        
    except Exception as e:
        results['error'] = str(e)
        results['summary']['mode'] = 'degraded'
    
    return results

def _collect_macos_users() -> Dict[str, Any]:
    """Collecte les utilisateurs macOS"""
    results = {
        'system_info': get_system_info(),
        'data': {'users': [], 'groups': [], 'sessions': []},
        'summary': {'total_users': 0, 'total_groups': 0, 'total_sessions': 0},
        'error': None
    }
    
    try:
        import subprocess
        
        # Collecte des utilisateurs via dscl
        try:
            output = subprocess.check_output(['dscl', '.', 'list', '/Users'], text=True, capture_output=True)
            users = []
            for line in output.split('\n'):
                if line.strip() and not line.startswith('_'):
                    users.append(line.strip())
            
            results['data']['users'] = users
            results['summary']['total_users'] = len(users)
        except:
            pass
        
        # Collecte des groupes via dscl
        try:
            output = subprocess.check_output(['dscl', '.', 'list', '/Groups'], text=True, capture_output=True)
            groups = []
            for line in output.split('\n'):
                if line.strip() and not line.startswith('_'):
                    groups.append(line.strip())
            
            results['data']['groups'] = groups
            results['summary']['total_groups'] = len(groups)
        except:
            pass
        
        # Collecte des sessions via who
        try:
            output = subprocess.check_output(['who'], text=True, capture_output=True)
            sessions = []
            for line in output.split('\n'):
                if line.strip():
                    sessions.append(line.strip())
            
            results['data']['sessions'] = sessions
            results['summary']['total_sessions'] = len(sessions)
        except:
            pass
        
        results['summary']['timestamp'] = datetime.now().isoformat()
        results['summary']['mode'] = 'full'
        
    except Exception as e:
        results['error'] = str(e)
        results['summary']['mode'] = 'degraded'
    
    return results

def collect_processes() -> Dict[str, Any]:
    """Collecteur de processus robuste"""
    results = {
        'system_info': get_system_info(),
        'data': {'processes': []},
        'summary': {'total_processes': 0},
        'error': None
    }
    
    try:
        import psutil
        
        processes = []
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cpu_percent', 'memory_percent', 'create_time']):
            try:
                proc_info = proc.info
                processes.append({
                    'pid': proc_info['pid'],
                    'name': proc_info['name'],
                    'username': proc_info['username'],
                    'cpu_percent': proc_info['cpu_percent'],
                    'memory_percent': proc_info['memory_percent'],
                    'create_time': datetime.fromtimestamp(proc_info['create_time']).isoformat()
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        
        results['data']['processes'] = processes
        results['summary']['total_processes'] = len(processes)
        results['summary']['timestamp'] = datetime.now().isoformat()
        results['summary']['mode'] = 'full'
        
    except Exception as e:
        results['error'] = str(e)
        results['summary']['mode'] = 'degraded'
    
    return results

def collect_network() -> Dict[str, Any]:
    """Collecteur réseau robuste"""
    results = {
        'system_info': get_system_info(),
        'data': {'connections': [], 'interfaces': []},
        'summary': {'total_connections': 0, 'total_interfaces': 0},
        'error': None
    }
    
    try:
        import psutil
        
        # Connexions réseau
        connections = []
        for conn in psutil.net_connections():
            try:
                connections.append({
                    'fd': conn.fd,
                    'family': str(conn.family),
                    'type': str(conn.type),
                    'laddr': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'raddr': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status,
                    'pid': conn.pid
                })
            except:
                continue
        
        # Interfaces réseau
        interfaces = []
        for name, addrs in psutil.net_if_addrs().items():
            try:
                interface_info = {'name': name, 'addresses': []}
                for addr in addrs:
                    interface_info['addresses'].append({
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast
                    })
                interfaces.append(interface_info)
            except:
                continue
        
        results['data']['connections'] = connections
        results['data']['interfaces'] = interfaces
        results['summary']['total_connections'] = len(connections)
        results['summary']['total_interfaces'] = len(interfaces)
        results['summary']['timestamp'] = datetime.now().isoformat()
        results['summary']['mode'] = 'full'
        
    except Exception as e:
        results['error'] = str(e)
        results['summary']['mode'] = 'degraded'
    
    return results

def collect_all() -> Dict[str, Any]:
    """Exécute tous les collecteurs disponibles"""
    collectors = list_available_collectors()
    current_platform = get_system_info()['platform']
    
    if current_platform == 'windows':
        platform_collectors = collectors.get('windows', [])
    elif current_platform == 'linux':
        platform_collectors = collectors.get('linux', [])
    elif current_platform == 'darwin':
        platform_collectors = collectors.get('macos', [])
    else:
        platform_collectors = []
    
    results = {
        'system_info': get_system_info(),
        'collectors': {},
        'summary': {
            'total_collectors': len(platform_collectors),
            'successful_collectors': 0,
            'failed_collectors': 0,
            'timestamp': datetime.now().isoformat()
        }
    }
    
    # Mapping des collecteurs
    collector_functions = {
        'users': collect_users,
        'processes': collect_processes,
        'network': collect_network
    }
    
    for collector_name in platform_collectors:
        try:
            if collector_name in collector_functions:
                logger.info(f"Exécution du collecteur: {collector_name}")
                results['collectors'][collector_name] = collector_functions[collector_name]()
                results['summary']['successful_collectors'] += 1
            else:
                logger.warning(f"Collecteur non implémenté: {collector_name}")
                results['collectors'][collector_name] = {'error': 'Collecteur non implémenté'}
                results['summary']['failed_collectors'] += 1
        except Exception as e:
            logger.error(f"Erreur dans le collecteur {collector_name}: {e}")
            results['collectors'][collector_name] = {'error': str(e)}
            results['summary']['failed_collectors'] += 1
    
    return results

def save_results(results: Dict[str, Any], output_file: str):
    """Sauvegarde les résultats dans un fichier JSON"""
    try:
        output_path = Path(output_file)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        logger.info(f"Résultats sauvegardés dans: {output_path}")
        return True
    except Exception as e:
        logger.error(f"Erreur lors de la sauvegarde: {e}")
        return False

def main():
    """Fonction principale"""
    parser = setup_argparse()
    args = parser.parse_args()
    
    # Configuration du logging
    if args.quiet:
        logging.getLogger().setLevel(logging.ERROR)
    elif args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    logger.info("Démarrage d'Osiris")
    
    try:
        if args.system_info:
            info = get_system_info()
            print(json.dumps(info, indent=2))
            return 0
        
        elif args.list:
            collectors = list_available_collectors()
            print("Collecteurs disponibles:")
            for platform, collector_list in collectors.items():
                print(f"\n{platform.upper()}:")
                for collector in collector_list:
                    print(f"  • {collector}")
            return 0
        
        elif args.collect:
            logger.info(f"Exécution du collecteur: {args.collect}")
            
            # Vérifier si le collecteur existe
            collectors = list_available_collectors()
            current_platform = get_system_info()['platform']
            
            if current_platform == 'windows':
                available_collectors = collectors.get('windows', [])
            elif current_platform == 'linux':
                available_collectors = collectors.get('linux', [])
            elif current_platform == 'darwin':
                available_collectors = collectors.get('macos', [])
            else:
                available_collectors = []
            
            if args.collect not in available_collectors:
                logger.error(f"Collecteur inconnu: {args.collect}")
                print(f"❌ Collecteur '{args.collect}' non disponible")
                print(f"📋 Collecteurs disponibles: {', '.join(available_collectors)}")
                return 1
            
            # Exécuter le collecteur
            if args.collect == 'users':
                results = collect_users()
            elif args.collect == 'processes':
                results = collect_processes()
            elif args.collect == 'network':
                results = collect_network()
            else:
                logger.error(f"Collecteur non implémenté: {args.collect}")
                print(f"❌ Collecteur '{args.collect}' non encore implémenté")
                return 1
            
            if args.output:
                save_results(results, args.output)
            else:
                print(json.dumps(results, indent=2))
            
            return 0
        
        elif args.collect_all:
            logger.info("Exécution de tous les collecteurs")
            results = collect_all()
            
            if args.output:
                save_results(results, args.output)
            else:
                print(json.dumps(results, indent=2))
            
            return 0
        
        else:
            parser.print_help()
            return 1
    
    except KeyboardInterrupt:
        logger.info("Interruption utilisateur")
        return 1
    except Exception as e:
        logger.error(f"Erreur fatale: {e}")
        return 1

if __name__ == '__main__':
    sys.exit(main()) 