import subprocess
import logging
from typing import List, Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)

class NetworkConnectionsCollector:
    """Collecte les connexions réseau Linux."""
    
    def __init__(self):
        self.geoip_enabled = False
        try:
            import geoip2.database
            self.geoip_enabled = True
        except ImportError:
            logger.info("GeoIP2 not available - geolocation disabled")
    
    def collect(self) -> List[Dict[str, Any]]:
        """Collecte toutes les connexions réseau actives."""
        results = []
        
        try:
            # Collecter les connexions TCP
            tcp_connections = self._collect_tcp_connections()
            results.extend(tcp_connections)
            
            # Collecter les connexions UDP
            udp_connections = self._collect_udp_connections()
            results.extend(udp_connections)
            
        except Exception as e:
            logger.error(f"Error collecting network connections: {e}")
        
        return results
    
    def _collect_tcp_connections(self) -> List[Dict[str, Any]]:
        """Collecte les connexions TCP."""
        try:
            cmd = ['ss', '-tuln', '--numeric']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                logger.error(f"ss command failed: {result.stderr}")
                return []
            
            connections = []
            lines = result.stdout.splitlines()
            
            for line in lines[1:]:  # Skip header
                if line.strip():
                    parsed = self._parse_ss_line(line, 'tcp')
                    if parsed:
                        connections.append(parsed)
            
            return connections
        
        except subprocess.TimeoutExpired:
            logger.warning("Timeout collecting TCP connections")
            return []
        except Exception as e:
            logger.error(f"Error collecting TCP connections: {e}")
            return []
    
    def _collect_udp_connections(self) -> List[Dict[str, Any]]:
        """Collecte les connexions UDP."""
        try:
            cmd = ['ss', '-uuln', '--numeric']
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                logger.error(f"ss command failed: {result.stderr}")
                return []
            
            connections = []
            lines = result.stdout.splitlines()
            
            for line in lines[1:]:  # Skip header
                if line.strip():
                    parsed = self._parse_ss_line(line, 'udp')
                    if parsed:
                        connections.append(parsed)
            
            return connections
        
        except subprocess.TimeoutExpired:
            logger.warning("Timeout collecting UDP connections")
            return []
        except Exception as e:
            logger.error(f"Error collecting UDP connections: {e}")
            return []
    
    def _parse_ss_line(self, line: str, protocol: str) -> Dict[str, Any]:
        """Parse une ligne de sortie ss."""
        try:
            parts = line.split()
            if len(parts) < 4:
                return None
            
            # Format: Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port
            netid = parts[0]
            state = parts[1]
            local_addr_port = parts[3]
            peer_addr_port = parts[4] if len(parts) > 4 else '*:*'
            
            # Parser les adresses
            local_addr, local_port = self._parse_addr_port(local_addr_port)
            peer_addr, peer_port = self._parse_addr_port(peer_addr_port)
            
            # Enrichir avec la géolocalisation si disponible
            geo_info = {}
            if self.geoip_enabled and peer_addr != '*' and peer_addr != '127.0.0.1':
                geo_info = self._get_geo_info(peer_addr)
            
            return {
                'type': 'network_connection',
                'protocol': protocol,
                'state': state,
                'local_address': local_addr,
                'local_port': local_port,
                'peer_address': peer_addr,
                'peer_port': peer_port,
                'geo_country': geo_info.get('country', 'Unknown'),
                'geo_city': geo_info.get('city', 'Unknown'),
                'geo_isp': geo_info.get('isp', 'Unknown'),
                'timestamp': datetime.now().isoformat()
            }
        
        except Exception as e:
            logger.error(f"Error parsing ss line: {e}")
            return None
    
    def _parse_addr_port(self, addr_port: str) -> tuple[str, str]:
        """Parse une adresse:port."""
        if addr_port == '*:*':
            return '*', '*'
        
        if ':' in addr_port:
            addr, port = addr_port.rsplit(':', 1)
            return addr, port
        
        return addr_port, '*'
    
    def _get_geo_info(self, ip: str) -> Dict[str, str]:
        """Récupère les informations géographiques d'une IP."""
        try:
            import geoip2.database
            
            # En production, utiliser une vraie base GeoIP
            # Pour l'instant, simulation basique
            if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
                return {'country': 'Local', 'city': 'Internal', 'isp': 'Internal'}
            elif ip.startswith('8.8.8.') or ip.startswith('8.8.4.'):
                return {'country': 'US', 'city': 'Mountain View', 'isp': 'Google'}
            else:
                return {'country': 'Unknown', 'city': 'Unknown', 'isp': 'Unknown'}
        
        except Exception as e:
            logger.error(f"Error getting geo info for {ip}: {e}")
            return {'country': 'Unknown', 'city': 'Unknown', 'isp': 'Unknown'}
    
    def get_established_connections(self) -> List[Dict[str, Any]]:
        """Récupère seulement les connexions établies."""
        all_connections = self.collect()
        return [conn for conn in all_connections if conn.get('state') == 'ESTAB']
    
    def get_listening_ports(self) -> List[Dict[str, Any]]:
        """Récupère les ports en écoute."""
        all_connections = self.collect()
        return [conn for conn in all_connections if conn.get('state') == 'LISTEN'] 