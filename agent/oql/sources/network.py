import psutil
import logging
from google.protobuf.struct_pb2 import Struct
import socket

# Un dictionnaire pour traduire les constantes de famille d'adresses en chaînes de caractères lisibles.
ADDRESS_FAMILY = {
    socket.AF_INET: 'AF_INET',
    socket.AF_INET6: 'AF_INET6',
}

# Un dictionnaire pour traduire les constantes de type de socket en chaînes de caractères lisibles.
SOCKET_TYPE = {
    socket.SOCK_STREAM: 'TCP',
    socket.SOCK_DGRAM: 'UDP',
}

class NetworkSource:
    """
    Une source de données OQL qui fournit la liste des connexions réseau actives.
    """
    def collect(self):
        """
        Collecte les informations sur les connexions et les retourne en tant que générateur.
        """
        # 'inet' récupère les connexions TCP et UDP pour IPv4 et IPv6.
        try:
            connections = psutil.net_connections(kind='inet')
        except psutil.AccessDenied:
            logging.error("Accès refusé lors de la collecte des connexions réseau. L'agent est-il exécuté avec les droits suffisants ?")
            return
            
        for conn in connections:
            try:
                s = Struct()
                
                # Informations sur l'adresse locale
                local_ip, local_port = conn.laddr if conn.laddr else (None, None)
                
                # Informations sur l'adresse distante (peut être vide pour les sockets en écoute)
                remote_ip, remote_port = conn.raddr if conn.raddr else (None, None)

                s.update({
                    "family": ADDRESS_FAMILY.get(conn.family, str(conn.family)),
                    "type": SOCKET_TYPE.get(conn.type, str(conn.type)),
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "status": conn.status,
                    "pid": conn.pid,
                })
                yield s

            except Exception as e:
                logging.error(f"Erreur inattendue lors du traitement d'une connexion: {e}")
                continue 