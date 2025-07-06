"""
Collecteur pour les informations réseau Linux
Collecte les connexions réseau, interfaces, etc.
"""

import os
import re
from datetime import datetime
from typing import Dict, List, Any
from .base import LinuxCollector

class NetworkCollector(LinuxCollector):
    """Collecteur pour les informations réseau Linux"""
    
    def __init__(self):
        super().__init__()
    
    def collect(self) -> Dict[str, Any]:
        """Collecte les informations réseau"""
        results = {
            'system_info': self.get_system_info(),
            'interfaces': [],
            'connections': [],
            'routing': {},
            'dns': {},
            'arp_table': [],
            'listening_ports': [],
            'suspicious_connections': [],
            'summary': {}
        }
        
        # Collecter les interfaces réseau
        results['interfaces'] = self._collect_network_interfaces()
        
        # Collecter les connexions réseau
        results['connections'] = self._collect_network_connections()
        
        # Collecter la table de routage
        results['routing'] = self._collect_routing_table()
        
        # Collecter les informations DNS
        results['dns'] = self._collect_dns_info()
        
        # Collecter la table ARP
        results['arp_table'] = self._collect_arp_table()
        
        # Collecter les ports en écoute
        results['listening_ports'] = self._collect_listening_ports()
        
        # Analyser les connexions suspectes
        results['suspicious_connections'] = self._analyze_suspicious_connections(results['connections'])
        
        # Générer un résumé
        results['summary'] = self._generate_summary(results)
        
        return results
    
    def _collect_network_interfaces(self) -> List[Dict[str, Any]]:
        """Collecte les interfaces réseau"""
        interfaces = []
        
        try:
            # Utiliser ip addr show
            result = self.execute_command(['ip', 'addr', 'show'])
            
            if result['success']:
                current_interface = None
                lines = result['stdout'].split('\n')
                
                for line in lines:
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Nouvelle interface
                    if line[0].isdigit():
                        if current_interface:
                            interfaces.append(current_interface)
                        
                        # Parse: 1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
                        match = re.match(r'(\d+):\s+(\w+):\s+<([^>]+)>\s+mtu\s+(\d+)', line)
                        if match:
                            current_interface = {
                                'index': int(match.group(1)),
                                'name': match.group(2),
                                'flags': match.group(3).split(','),
                                'mtu': int(match.group(4)),
                                'addresses': []
                            }
                    
                    # Adresse IP
                    elif line.startswith('inet ') or line.startswith('inet6 '):
                        if current_interface:
                            # Parse: inet 127.0.0.1/8 scope host lo
                            match = re.match(r'(inet6?)\s+([^/]+)/(\d+)\s+scope\s+(\w+)', line)
                            if match:
                                current_interface['addresses'].append({
                                    'family': match.group(1),
                                    'address': match.group(2),
                                    'prefix': int(match.group(3)),
                                    'scope': match.group(4)
                                })
                
                # Ajouter la dernière interface
                if current_interface:
                    interfaces.append(current_interface)
            
            # Collecter les statistiques des interfaces
            for interface in interfaces:
                interface['statistics'] = self._get_interface_statistics(interface['name'])
        
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte des interfaces réseau: {e}")
        
        return interfaces
    
    def _get_interface_statistics(self, interface_name: str) -> Dict[str, Any]:
        """Récupère les statistiques d'une interface"""
        stats = {}
        
        try:
            # Lire /proc/net/dev
            with open('/proc/net/dev', 'r') as f:
                for line in f:
                    if interface_name in line:
                        parts = line.split()
                        if len(parts) >= 17:
                            stats = {
                                'rx_bytes': int(parts[1]),
                                'rx_packets': int(parts[2]),
                                'rx_errors': int(parts[3]),
                                'rx_dropped': int(parts[4]),
                                'tx_bytes': int(parts[9]),
                                'tx_packets': int(parts[10]),
                                'tx_errors': int(parts[11]),
                                'tx_dropped': int(parts[12])
                            }
                        break
        except:
            pass
        
        return stats
    
    def _collect_network_connections(self) -> List[Dict[str, Any]]:
        """Collecte les connexions réseau"""
        connections = []
        
        try:
            # Utiliser ss pour les connexions
            result = self.execute_command(['ss', '-tuln', '--numeric'])
            
            if result['success']:
                lines = result['stdout'].split('\n')
                
                for line in lines[1:]:  # Ignorer l'en-tête
                    if line.strip():
                        # Parse: tcp    LISTEN 0      128    127.0.0.1:631       0.0.0.0:*
                        parts = line.split()
                        if len(parts) >= 5:
                            connection = {
                                'protocol': parts[0],
                                'state': parts[1],
                                'recv_q': int(parts[2]),
                                'send_q': int(parts[3]),
                                'local_address': parts[4],
                                'peer_address': parts[5] if len(parts) > 5 else '*:*'
                            }
                            connections.append(connection)
            
            # Collecter les connexions établies avec ss -tuln
            result = self.execute_command(['ss', '-tuln', '--numeric', '--processes'])
            
            if result['success']:
                lines = result['stdout'].split('\n')
                
                for line in lines[1:]:
                    if line.strip():
                        # Parse avec processus: tcp    ESTAB 0      0      192.168.1.100:22      192.168.1.1:12345    users:(("sshd",pid=1234,fd=3))
                        match = re.search(r'users:\(\("([^"]+)",pid=(\d+),fd=(\d+)\)\)', line)
                        if match:
                            # Trouver la connexion correspondante
                            for conn in connections:
                                if conn['local_address'] in line and conn['peer_address'] in line:
                                    conn['process'] = {
                                        'name': match.group(1),
                                        'pid': int(match.group(2)),
                                        'fd': int(match.group(3))
                                    }
                                    break
        
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte des connexions réseau: {e}")
        
        return connections
    
    def _collect_routing_table(self) -> Dict[str, Any]:
        """Collecte la table de routage"""
        routing = {}
        
        try:
            # Table de routage IPv4
            result = self.execute_command(['ip', 'route', 'show'])
            if result['success']:
                routing['ipv4'] = []
                for line in result['stdout'].split('\n'):
                    if line.strip():
                        routing['ipv4'].append(line.strip())
            
            # Table de routage IPv6
            result = self.execute_command(['ip', '-6', 'route', 'show'])
            if result['success']:
                routing['ipv6'] = []
                for line in result['stdout'].split('\n'):
                    if line.strip():
                        routing['ipv6'].append(line.strip())
            
            # Informations sur les règles de routage
            result = self.execute_command(['ip', 'rule', 'show'])
            if result['success']:
                routing['rules'] = []
                for line in result['stdout'].split('\n'):
                    if line.strip():
                        routing['rules'].append(line.strip())
        
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte de la table de routage: {e}")
        
        return routing
    
    def _collect_dns_info(self) -> Dict[str, Any]:
        """Collecte les informations DNS"""
        dns_info = {}
        
        try:
            # Lire /etc/resolv.conf
            if os.path.exists('/etc/resolv.conf'):
                dns_info['resolv_conf'] = self.read_file_lines('/etc/resolv.conf')
            
            # Lire /etc/hosts
            if os.path.exists('/etc/hosts'):
                dns_info['hosts'] = self.read_file_lines('/etc/hosts')
            
            # Collecter les serveurs DNS actifs
            dns_info['active_servers'] = []
            
            # Vérifier les serveurs DNS dans resolv.conf
            if 'resolv_conf' in dns_info:
                for line in dns_info['resolv_conf']:
                    if line.startswith('nameserver'):
                        server = line.split()[1]
                        dns_info['active_servers'].append(server)
            
            # Test de résolution DNS
            dns_info['resolution_tests'] = []
            test_domains = ['google.com', 'github.com', 'example.com']
            
            for domain in test_domains:
                result = self.execute_command(['nslookup', domain], timeout=5)
                dns_info['resolution_tests'].append({
                    'domain': domain,
                    'success': result['success'],
                    'output': result['stdout'] if result['success'] else result['stderr']
                })
        
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte des informations DNS: {e}")
        
        return dns_info
    
    def _collect_arp_table(self) -> List[Dict[str, Any]]:
        """Collecte la table ARP"""
        arp_table = []
        
        try:
            result = self.execute_command(['ip', 'neigh', 'show'])
            
            if result['success']:
                for line in result['stdout'].split('\n'):
                    if line.strip():
                        # Parse: 192.168.1.1 dev eth0 lladdr 00:11:22:33:44:55 REACHABLE
                        parts = line.split()
                        if len(parts) >= 4:
                            arp_entry = {
                                'ip_address': parts[0],
                                'interface': parts[2],
                                'mac_address': parts[4],
                                'state': parts[5] if len(parts) > 5 else 'UNKNOWN'
                            }
                            arp_table.append(arp_entry)
        
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte de la table ARP: {e}")
        
        return arp_table
    
    def _collect_listening_ports(self) -> List[Dict[str, Any]]:
        """Collecte les ports en écoute"""
        listening_ports = []
        
        try:
            # Utiliser ss pour les ports en écoute
            result = self.execute_command(['ss', '-tuln', '--listening', '--numeric', '--processes'])
            
            if result['success']:
                lines = result['stdout'].split('\n')
                
                for line in lines[1:]:  # Ignorer l'en-tête
                    if line.strip():
                        # Parse: tcp    LISTEN 0      128    127.0.0.1:631       0.0.0.0:*    users:(("cupsd",pid=1234,fd=3))
                        parts = line.split()
                        if len(parts) >= 5:
                            port_info = {
                                'protocol': parts[0],
                                'state': parts[1],
                                'local_address': parts[4],
                                'process': None
                            }
                            
                            # Extraire les informations du processus
                            match = re.search(r'users:\(\("([^"]+)",pid=(\d+),fd=(\d+)\)\)', line)
                            if match:
                                port_info['process'] = {
                                    'name': match.group(1),
                                    'pid': int(match.group(2)),
                                    'fd': int(match.group(3))
                                }
                            
                            listening_ports.append(port_info)
        
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte des ports en écoute: {e}")
        
        return listening_ports
    
    def _analyze_suspicious_connections(self, connections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyse les connexions suspectes"""
        suspicious_connections = []
        
        # Ports suspects
        suspicious_ports = {
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            443: 'HTTPS',
            445: 'SMB',
            1433: 'MSSQL',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            5900: 'VNC',
            8080: 'HTTP Proxy',
            8443: 'HTTPS Alternative'
        }
        
        # Adresses suspectes
        suspicious_patterns = [
            r'\b(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)',  # Adresses privées
            r'\b(127\.0\.0\.1|localhost)\b',  # Localhost
            r'\b(0\.0\.0\.0)\b',  # Toutes les interfaces
        ]
        
        for conn in connections:
            suspicious_flags = []
            
            # Vérifier les ports suspects
            local_addr = conn.get('local_address', '')
            peer_addr = conn.get('peer_address', '')
            
            for addr in [local_addr, peer_addr]:
                if ':' in addr:
                    try:
                        port = int(addr.split(':')[1])
                        if port in suspicious_ports:
                            suspicious_flags.append(f"Port suspect: {port} ({suspicious_ports[port]})")
                    except:
                        pass
            
            # Vérifier les adresses suspectes
            for pattern in suspicious_patterns:
                if re.search(pattern, local_addr) or re.search(pattern, peer_addr):
                    suspicious_flags.append(f"Adresse suspecte: {local_addr} -> {peer_addr}")
            
            # Vérifier les connexions établies vers des adresses externes
            if conn.get('state') == 'ESTAB' and peer_addr != '*:*':
                if not any(re.search(pattern, peer_addr) for pattern in suspicious_patterns):
                    suspicious_flags.append(f"Connexion externe établie: {peer_addr}")
            
            # Si des flags suspects sont trouvés
            if suspicious_flags:
                suspicious_connections.append({
                    'connection': conn,
                    'suspicious_flags': suspicious_flags,
                    'risk_level': self._assess_connection_risk(suspicious_flags)
                })
        
        return suspicious_connections
    
    def _assess_connection_risk(self, flags: List[str]) -> str:
        """Évalue le niveau de risque d'une connexion"""
        high_risk_flags = [
            "Connexion externe établie:",
            "Port suspect: 23 (Telnet)",
            "Port suspect: 445 (SMB)"
        ]
        
        medium_risk_flags = [
            "Port suspect: 22 (SSH)",
            "Port suspect: 3389 (RDP)",
            "Adresse suspecte:"
        ]
        
        if any(any(high_flag in flag for high_flag in high_risk_flags) for flag in flags):
            return 'high'
        elif any(any(medium_flag in flag for medium_flag in medium_risk_flags) for flag in flags):
            return 'medium'
        else:
            return 'low'
    
    def _generate_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Génère un résumé des informations réseau"""
        try:
            interfaces = results.get('interfaces', [])
            connections = results.get('connections', [])
            suspicious = results.get('suspicious_connections', [])
            listening = results.get('listening_ports', [])
            
            # Statistiques des interfaces
            interface_stats = {
                'total_interfaces': len(interfaces),
                'up_interfaces': len([i for i in interfaces if 'UP' in i.get('flags', [])]),
                'loopback_interfaces': len([i for i in interfaces if 'LOOPBACK' in i.get('flags', [])])
            }
            
            # Statistiques des connexions
            connection_stats = {
                'total_connections': len(connections),
                'established_connections': len([c for c in connections if c.get('state') == 'ESTAB']),
                'listening_connections': len([c for c in connections if c.get('state') == 'LISTEN'])
            }
            
            # Statistiques des ports en écoute
            listening_stats = {
                'total_listening_ports': len(listening),
                'tcp_ports': len([p for p in listening if p.get('protocol') == 'tcp']),
                'udp_ports': len([p for p in listening if p.get('protocol') == 'udp'])
            }
            
            return {
                'interface_statistics': interface_stats,
                'connection_statistics': connection_stats,
                'listening_port_statistics': listening_stats,
                'suspicious_connections_count': len(suspicious),
                'high_risk_connections': len([c for c in suspicious if c.get('risk_level') == 'high']),
                'medium_risk_connections': len([c for c in suspicious if c.get('risk_level') == 'medium']),
                'low_risk_connections': len([c for c in suspicious if c.get('risk_level') == 'low']),
                'arp_entries_count': len(results.get('arp_table', [])),
                'dns_servers_count': len(results.get('dns', {}).get('active_servers', []))
            }
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la génération du résumé: {e}")
            return {'error': str(e)} 