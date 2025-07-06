import subprocess
import re
import ipaddress
import geoip2.database
from dataclasses import dataclass, field
from typing import Iterator, Optional

@dataclass
class NetConnection:
    protocol: str
    state: str
    local_address: str
    local_port: Optional[int]
    peer_address: str
    peer_port: Optional[int]
    process_name: Optional[str]
    pid: Optional[int]
    user: Optional[str]
    is_private_ip: bool
    geo_country: Optional[str] = None
    geo_city: Optional[str] = None

class NetworkConnectionsCollector:
    """
    Collecte les connexions réseau actives via la commande 'ss'.
    """
    PROCESS_REGEX = re.compile(r'users:\(\("(?P<name>[^"]+)",pid=(?P<pid>\d+),.*?\)\)')

    def __init__(self, geoip_db_path="agent/data/GeoLite2-City.mmdb"):
        """Initialise le collecteur et charge la base GeoIP si elle existe."""
        self.geoip_reader = None
        try:
            self.geoip_reader = geoip2.database.Reader(geoip_db_path)
            print("Base de données GeoIP chargée avec succès.")
        except FileNotFoundError:
            print("Base de données GeoIP non trouvée. L'enrichissement sera désactivé.")
        except Exception as e:
            print(f"Erreur lors du chargement de la base GeoIP: {e}")

    def _parse_address(self, addr_str: str) -> (str, Optional[int]):
        """Sépare l'adresse IP du port."""
        try:
            if addr_str.count(':') > 1:  # IPv6
                parts = addr_str.rsplit(':', 1)
                address = parts[0]
                port = int(parts[1]) if parts[1].isdigit() else None
            else:  # IPv4
                address, port_str = addr_str.rsplit(':', 1)
                port = int(port_str) if port_str.isdigit() else None
            return address, port
        except (ValueError, IndexError):
            return addr_str, None

    def _enrich_ip(self, ip_str: str) -> dict:
        """Enrichit une adresse IP avec des données de géolocalisation."""
        enrichment_data = {"is_private_ip": False, "geo_country": None, "geo_city": None}
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private or ip_obj.is_loopback:
                enrichment_data["is_private_ip"] = True
                return enrichment_data

            if self.geoip_reader:
                response = self.geoip_reader.city(ip_str)
                enrichment_data["geo_country"] = response.country.name
                enrichment_data["geo_city"] = response.city.name
        
        except (ValueError, geoip2.errors.AddressNotFoundError):
            # Ignore les IP invalides ou non trouvées dans la base
            pass
        return enrichment_data

    def collect(self) -> Iterator[NetConnection]:
        command = ["ss", "-tupna"]
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()

            if process.returncode != 0:
                print(f"Error running ss command: {stderr}")
                return

            lines = stdout.strip().split('\n')
            if not lines:
                return
            header = lines[0]

            for line in lines[1:]:
                parts = line.split()
                if len(parts) < 6:
                    continue
                proto = parts[0]
                state = parts[1] if proto in ['tcp', 'udp'] else 'UNKNOWN'
                addr_index_offset = 1 if state in ['LISTEN', 'UNCONN'] else 0
                local_addr_str = parts[2 + addr_index_offset]
                peer_addr_str = parts[3 + addr_index_offset]
                process_info_str = parts[-1]
                local_addr, local_port = self._parse_address(local_addr_str)
                peer_addr, peer_port = self._parse_address(peer_addr_str)
                proc_name, proc_pid, proc_user = None, None, None
                match = self.PROCESS_REGEX.search(process_info_str)
                if match:
                    proc_name = match.group('name')
                    proc_pid = int(match.group('pid'))
                
                # Enrichir l'adresse IP distante
                enrichment = self._enrich_ip(peer_addr)

                yield NetConnection(
                    protocol=proto,
                    state=state,
                    local_address=local_addr,
                    local_port=local_port,
                    peer_address=peer_addr,
                    peer_port=peer_port,
                    process_name=proc_name,
                    pid=proc_pid,
                    user=proc_user,
                    is_private_ip=enrichment["is_private_ip"],
                    geo_country=enrichment["geo_country"],
                    geo_city=enrichment["geo_city"]
                )
        except FileNotFoundError:
            print("Command 'ss' not found. Is this a Linux system with iproute2 installed?")
        except Exception as e:
            print(f"An error occurred while collecting network connections: {e}")

if __name__ == '__main__':
    collector = NetworkConnectionsCollector()
    for conn in collector.collect():
        print(
            f"Proto: {conn.protocol}, State: {conn.state}, "
            f"Local: {conn.local_address}:{conn.local_port}, "
            f"Peer: {conn.peer_address}:{conn.peer_port}, "
            f"Process: {conn.process_name}({conn.pid}), "
            f"Private: {conn.is_private_ip}, "
            f"Country: {conn.geo_country}, "
            f"City: {conn.geo_city}"
        ) 