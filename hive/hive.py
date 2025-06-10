import grpc
from concurrent import futures
import time
import yaml
import logging
import os
import threading
from datetime import datetime

# Configuration pour trouver les fichiers .proto compilés
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../protos')))
import osiris_pb2
import osiris_pb2_grpc

# --- Gestion des Agents ---
# Dans un environnement de production, cela serait remplacé par une base de données (Redis, PostgreSQL...)
connected_agents = {}
agent_lock = threading.Lock()

def setup_logging(config):
    """Configure la journalisation (logging) pour le serveur."""
    log_level = config['logging']['level'].upper()
    log_file = config['logging']['file']
    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    logging.info("Logging configuré.")

class AgentCommsServicer(osiris_pb2_grpc.AgentCommsServicer):
    """Implémentation du service gRPC de communication."""

    def Heartbeat(self, request_iterator, context):
        agent_id = None
        peer_address = context.peer()
        
        try:
            # Le premier message de l'agent est un message d'enregistrement
            first_request = next(request_iterator)
            agent_id = first_request.agent_id
            
            with agent_lock:
                connected_agents[agent_id] = {
                    "hostname": first_request.hostname,
                    "os": first_request.os_type,
                    "version": first_request.version,
                    "ip": peer_address,
                    "last_seen": datetime.utcnow()
                }
            logging.info(f"Agent {agent_id} ({first_request.hostname}) enregistré depuis {peer_address}.")
            
            # Boucle de communication continue
            while context.is_active():
                # Ici, on pourrait chercher des instructions pour cet agent dans une file d'attente
                # Pour l'instant, on envoie juste une instruction vide (NOOP)
                yield osiris_pb2.HiveInstruction(
                    instruction_id="noop-1",
                    type=osiris_pb2.HiveInstruction.InstructionType.NOOP,
                    payload="stayin_alive"
                )
                
                # Mettre à jour l'heure de dernière communication
                with agent_lock:
                    if agent_id in connected_agents:
                        connected_agents[agent_id]["last_seen"] = datetime.utcnow()

                time.sleep(15) # Fréquence du heartbeat

        except grpc.RpcError:
            logging.warning(f"Connexion perdue avec l'agent {agent_id if agent_id else 'inconnu'} à {peer_address}.")
        finally:
            if agent_id:
                with agent_lock:
                    if agent_id in connected_agents:
                        del connected_agents[agent_id]
                        logging.info(f"Agent {agent_id} déconnecté et retiré du pool actif.")


def serve(config):
    """Démarre le serveur gRPC Hive."""
    logging.info("Démarrage du serveur Osiris Hive...")
    
    # Charger les certificats pour mTLS
    try:
        with open(config['security']['server_key_path'], 'rb') as f:
            private_key = f.read()
        with open(config['security']['server_cert_path'], 'rb') as f:
            certificate_chain = f.read()
        with open(config['security']['ca_cert_path'], 'rb') as f:
            ca_cert = f.read()
    except FileNotFoundError as e:
        logging.critical(f"Erreur de certificat: {e}. Avez-vous exécuté 'scripts/generate_certs.py'?")
        return

    # Créer les credentials du serveur avec mTLS
    server_credentials = grpc.ssl_server_credentials(
        private_key_certificate_chain_pairs=[(private_key, certificate_chain)],
        root_certificates=ca_cert,
        require_client_auth=True
    )

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=50))
    osiris_pb2_grpc.add_AgentCommsServicer_to_server(AgentCommsServicer(), server)
    
    server_address = f"{config['server']['host']}:{config['server']['port']}"
    server.add_secure_port(server_address, server_credentials)
    
    server.start()
    logging.info(f"Serveur Hive démarré sur {server_address} avec mTLS activé.")
    
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        logging.info("Arrêt du serveur Hive...")
        server.stop(0)
        logging.info("Serveur arrêté.")

if __name__ == '__main__':
    try:
        with open('hive/config.yaml', 'r') as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        print("[CRITICAL] Fichier de configuration 'hive/config.yaml' introuvable.")
        sys.exit(1)

    setup_logging(config)
    serve(config) 