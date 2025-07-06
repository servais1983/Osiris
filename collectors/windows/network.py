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
import socket
import struct
import ctypes
from ctypes import wintypes
import ipaddress
from .base import WindowsCollector

class WindowsNetworkCollector(WindowsCollector):
    """Collecteur pour les connexions réseau Windows"""
    
    def __init__(self):
        super().__init__()
        self.requires_admin = True
        
        # Définition des structures Windows pour les connexions réseau
        self.MIB_TCPROW_OWNER_PID = struct.Struct('IIIIIIII')
        self.MIB_TCPTABLE_OWNER_PID = struct.Struct('II')
        self.MIB_UDPROW_OWNER_PID = struct.Struct('IIIIII')
        self.MIB_UDPTABLE_OWNER_PID = struct.Struct('II')
    
    def collect(self) -> Dict[str, Any]:
        return super().collect()

    def _collect(self) -> Dict[str, Any]:
        results = {
            'system_info': self.get_system_info(),
            'connections': {
                'tcp': [],
                'udp': []
            },
            'interfaces': [],
            'routing': [],
            'dns': {},
            'arp': [],
            'firewall': [],
            'summary': {}
        }
        
        try:
            if not self.check_privileges():
                results['error'] = 'Privilèges insuffisants'
                return results
            
            results['connections']['tcp'] = self._get_tcp_connections()
            results['connections']['udp'] = self._get_udp_connections()
            results['interfaces'] = self._get_network_interfaces()
            results['routing'] = self._get_routing_table()
            results['dns'] = self._get_dns_info()
            results['arp'] = self._get_arp_table()
            results['firewall'] = self._get_firewall_rules()
            
            # Générer un résumé
            results['summary'] = {
                'total_tcp_connections': len(results['connections']['tcp']),
                'total_udp_connections': len(results['connections']['udp']),
                'total_interfaces': len(results['interfaces']),
                'total_routes': len(results['routing']),
                'total_arp_entries': len(results['arp']),
                'total_firewall_rules': len(results['firewall']),
                'timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la collecte des connexions réseau: {e}")
            results['error'] = str(e)
        
        return results
    
    def _get_tcp_connections(self) -> List[Dict[str, Any]]:
        """Récupère les connexions TCP"""
        connections = []
        
        try:
            # Récupération de la taille de la table TCP
            size = ctypes.c_ulong(0)
            ctypes.windll.iphlpapi.GetExtendedTcpTable(
                None,
                ctypes.byref(size),
                False,
                socket.AF_INET,
                5,  # TCP_TABLE_OWNER_PID_ALL
                0
            )
            
            # Allocation de la mémoire
            buffer = ctypes.create_string_buffer(size.value)
            
            # Récupération de la table TCP
            ctypes.windll.iphlpapi.GetExtendedTcpTable(
                buffer,
                ctypes.byref(size),
                False,
                socket.AF_INET,
                5,  # TCP_TABLE_OWNER_PID_ALL
                0
            )
            
            # Lecture de la table
            num_entries = self.MIB_TCPTABLE_OWNER_PID.unpack(buffer[:8])[0]
            
            for i in range(num_entries):
                offset = 8 + i * self.MIB_TCPROW_OWNER_PID.size
                row = self.MIB_TCPROW_OWNER_PID.unpack(buffer[offset:offset + self.MIB_TCPROW_OWNER_PID.size])
                
                # Conversion des adresses IP
                local_addr = socket.inet_ntoa(struct.pack('I', row[0]))
                remote_addr = socket.inet_ntoa(struct.pack('I', row[1]))
                
                # Conversion des ports
                local_port = socket.ntohs(row[2])
                remote_port = socket.ntohs(row[3])
                
                # État de la connexion
                state = self._get_tcp_state(row[4])
                
                # PID du processus
                pid = row[7]
                
                # Informations sur le processus
                try:
                    process = psutil.Process(pid)
                    process_name = process.name()
                    process_path = process.exe()
                except:
                    process_name = None
                    process_path = None
                
                connections.append({
                    'local_addr': local_addr,
                    'local_port': local_port,
                    'remote_addr': remote_addr,
                    'remote_port': remote_port,
                    'state': state,
                    'pid': pid,
                    'process_name': process_name,
                    'process_path': process_path
                })
            
            return connections
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des connexions TCP: {e}")
            return []
    
    def _get_udp_connections(self) -> List[Dict[str, Any]]:
        """Récupère les connexions UDP"""
        connections = []
        
        try:
            # Récupération de la taille de la table UDP
            size = ctypes.c_ulong(0)
            ctypes.windll.iphlpapi.GetExtendedUdpTable(
                None,
                ctypes.byref(size),
                False,
                socket.AF_INET,
                1,  # UDP_TABLE_OWNER_PID
                0
            )
            
            # Allocation de la mémoire
            buffer = ctypes.create_string_buffer(size.value)
            
            # Récupération de la table UDP
            ctypes.windll.iphlpapi.GetExtendedUdpTable(
                buffer,
                ctypes.byref(size),
                False,
                socket.AF_INET,
                1,  # UDP_TABLE_OWNER_PID
                0
            )
            
            # Lecture de la table
            num_entries = self.MIB_UDPTABLE_OWNER_PID.unpack(buffer[:8])[0]
            
            for i in range(num_entries):
                offset = 8 + i * self.MIB_UDPROW_OWNER_PID.size
                row = self.MIB_UDPROW_OWNER_PID.unpack(buffer[offset:offset + self.MIB_UDPROW_OWNER_PID.size])
                
                # Conversion de l'adresse IP
                local_addr = socket.inet_ntoa(struct.pack('I', row[0]))
                
                # Conversion du port
                local_port = socket.ntohs(row[1])
                
                # PID du processus
                pid = row[5]
                
                # Informations sur le processus
                try:
                    process = psutil.Process(pid)
                    process_name = process.name()
                    process_path = process.exe()
                except:
                    process_name = None
                    process_path = None
                
                connections.append({
                    'local_addr': local_addr,
                    'local_port': local_port,
                    'pid': pid,
                    'process_name': process_name,
                    'process_path': process_path
                })
            
            return connections
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des connexions UDP: {e}")
            return []
    
    def _get_network_interfaces(self) -> List[Dict[str, Any]]:
        """Récupère les informations sur les interfaces réseau"""
        interfaces = []
        
        try:
            # Récupération des interfaces
            for interface, addrs in psutil.net_if_addrs().items():
                interface_info = {
                    'name': interface,
                    'addresses': [],
                    'stats': None
                }
                
                # Adresses
                for addr in addrs:
                    interface_info['addresses'].append({
                        'family': str(addr.family),
                        'address': addr.address,
                        'netmask': addr.netmask,
                        'broadcast': addr.broadcast,
                        'ptp': addr.ptp
                    })
                
                # Statistiques
                try:
                    stats = psutil.net_if_stats()[interface]
                    interface_info['stats'] = {
                        'isup': stats.isup,
                        'duplex': stats.duplex,
                        'speed': stats.speed,
                        'mtu': stats.mtu
                    }
                except:
                    pass
                
                interfaces.append(interface_info)
            
            return interfaces
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des interfaces réseau: {e}")
            return []
    
    def _get_routing_table(self) -> List[Dict[str, Any]]:
        """Récupère la table de routage"""
        routes = []
        
        try:
            # Récupération de la table de routage
            for route in psutil.net_if_stats().keys():
                try:
                    # Exécution de la commande route print
                    output = os.popen('route print').read()
                    
                    # Parsing de la sortie
                    for line in output.split('\n'):
                        if line.strip() and not line.startswith('Network Destination'):
                            parts = line.split()
                            if len(parts) >= 4:
                                routes.append({
                                    'destination': parts[0],
                                    'netmask': parts[1],
                                    'gateway': parts[2],
                                    'interface': parts[3]
                                })
                except:
                    continue
            
            return routes
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération de la table de routage: {e}")
            return []
    
    def _get_dns_info(self) -> Dict[str, Any]:
        """Récupère les informations DNS"""
        dns_info = {}
        
        try:
            # Récupération des serveurs DNS
            dns_info['servers'] = []
            
            # Exécution de la commande ipconfig /all
            output = os.popen('ipconfig /all').read()
            
            # Parsing de la sortie
            for line in output.split('\n'):
                if 'DNS Servers' in line:
                    dns_servers = line.split(':')[1].strip().split()
                    dns_info['servers'].extend(dns_servers)
            
            # Récupération du cache DNS
            dns_info['cache'] = []
            
            # Exécution de la commande ipconfig /displaydns
            output = os.popen('ipconfig /displaydns').read()
            
            # Parsing de la sortie
            current_record = {}
            for line in output.split('\n'):
                if 'Record Name' in line:
                    if current_record:
                        dns_info['cache'].append(current_record)
                    current_record = {'name': line.split(':')[1].strip()}
                elif 'Record Type' in line:
                    current_record['type'] = line.split(':')[1].strip()
                elif 'Time To Live' in line:
                    current_record['ttl'] = line.split(':')[1].strip()
                elif 'Data Length' in line:
                    current_record['length'] = line.split(':')[1].strip()
                elif 'Section' in line:
                    current_record['section'] = line.split(':')[1].strip()
                elif 'A (Host) Record' in line:
                    current_record['address'] = line.split(':')[1].strip()
            
            if current_record:
                dns_info['cache'].append(current_record)
            
            return dns_info
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des informations DNS: {e}")
            return {}
    
    def _get_arp_table(self) -> List[Dict[str, Any]]:
        """Récupère la table ARP"""
        arp_table = []
        
        try:
            # Exécution de la commande arp -a
            output = os.popen('arp -a').read()
            
            # Parsing de la sortie
            for line in output.split('\n'):
                if line.strip() and not line.startswith('Interface'):
                    parts = line.split()
                    if len(parts) >= 2:
                        arp_table.append({
                            'ip_address': parts[0],
                            'mac_address': parts[1],
                            'type': parts[2] if len(parts) > 2 else None
                        })
            
            return arp_table
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération de la table ARP: {e}")
            return []
    
    def _get_firewall_rules(self) -> List[Dict[str, Any]]:
        """Récupère les règles du pare-feu"""
        rules = []
        
        try:
            # Exécution de la commande netsh advfirewall firewall show rule name=all
            output = os.popen('netsh advfirewall firewall show rule name=all').read()
            
            # Parsing de la sortie
            current_rule = {}
            for line in output.split('\n'):
                if line.strip():
                    if 'Rule Name' in line:
                        if current_rule:
                            rules.append(current_rule)
                        current_rule = {'name': line.split(':')[1].strip()}
                    elif 'Enabled' in line:
                        current_rule['enabled'] = line.split(':')[1].strip() == 'Yes'
                    elif 'Direction' in line:
                        current_rule['direction'] = line.split(':')[1].strip()
                    elif 'Profiles' in line:
                        current_rule['profiles'] = line.split(':')[1].strip()
                    elif 'Action' in line:
                        current_rule['action'] = line.split(':')[1].strip()
                    elif 'Program' in line:
                        current_rule['program'] = line.split(':')[1].strip()
                    elif 'LocalAddress' in line:
                        current_rule['local_address'] = line.split(':')[1].strip()
                    elif 'RemoteAddress' in line:
                        current_rule['remote_address'] = line.split(':')[1].strip()
                    elif 'LocalPort' in line:
                        current_rule['local_port'] = line.split(':')[1].strip()
                    elif 'RemotePort' in line:
                        current_rule['remote_port'] = line.split(':')[1].strip()
                    elif 'Protocol' in line:
                        current_rule['protocol'] = line.split(':')[1].strip()
            
            if current_rule:
                rules.append(current_rule)
            
            return rules
            
        except Exception as e:
            self.logger.error(f"Erreur lors de la récupération des règles du pare-feu: {e}")
            return []
    
    def _get_tcp_state(self, state: int) -> str:
        """Convertit l'état TCP en chaîne de caractères"""
        states = {
            1: 'CLOSED',
            2: 'LISTENING',
            3: 'SYN_SENT',
            4: 'SYN_RCVD',
            5: 'ESTABLISHED',
            6: 'FIN_WAIT1',
            7: 'FIN_WAIT2',
            8: 'CLOSE_WAIT',
            9: 'CLOSING',
            10: 'LAST_ACK',
            11: 'TIME_WAIT',
            12: 'DELETE_TCB'
        }
        return states.get(state, 'UNKNOWN') 