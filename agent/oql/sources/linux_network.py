"""
Source OQL pour les informations réseau Linux
"""

import logging
from typing import Dict, List, Any
from collectors.linux import NetworkCollector

logger = logging.getLogger(__name__)

class LinuxNetworkSource:
    """Source OQL pour les informations réseau Linux"""
    
    def __init__(self):
        self.collector = NetworkCollector()
    
    def collect(self) -> List[Dict[str, Any]]:
        """Collecte les informations réseau Linux"""
        try:
            results = self.collector.collect()
            
            all_network_data = []
            
            # Interfaces réseau
            for interface in results.get('interfaces', []):
                interface['type'] = 'interface'
                interface['source'] = 'linux_network'
                all_network_data.append(interface)
            
            # Connexions réseau
            for connection in results.get('connections', []):
                connection['type'] = 'connection'
                connection['source'] = 'linux_network'
                all_network_data.append(connection)
            
            # Ports en écoute
            for port in results.get('listening_ports', []):
                port['type'] = 'listening_port'
                port['source'] = 'linux_network'
                all_network_data.append(port)
            
            # Entrées ARP
            for arp_entry in results.get('arp_table', []):
                arp_entry['type'] = 'arp_entry'
                arp_entry['source'] = 'linux_network'
                all_network_data.append(arp_entry)
            
            return all_network_data
            
        except Exception as e:
            logger.error(f"Erreur lors de la collecte des informations réseau: {e}")
            return [] 