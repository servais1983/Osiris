import grpc
import yaml
import logging
import os
import uuid
import platform
import socket
import time
import sys

# Configuration pour trouver les fichiers .proto compilés
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../protos')))
import osiris_pb2
import osiris_pb2_grpc

def setup_logging(config):
    """Configure la journalisation (logging) pour l'agent."""
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

def get_agent_id(config):
    """Récupère ou génère un ID unique pour l'agent."""
    if config['agent']['id']:
        return config['agent']['id']
    # Pour un déploiement réel, cet ID devrait être stocké sur le disque
    # pour persister entre les redémarrages.
    return str(uuid.uuid4())

def initial_registration_message(agent_id, config):
    """Crée le premier message envoyé au Hive."""
    hostname = socket.gethostname()
    os_type = f"{platform.system()} {platform.release()}"
    return osiris_pb2.RegistrationRequest(
        agent_id=agent_id,
        hostname=hostname,
        os_type=os_type,
        version=config['agent']['version']
    )

def handle_hive_instructions(instruction_iterator):
    """Traite les instructions reçues du serveur Hive."""
    try:
        for instruction in instruction_iterator:
            logging.debug(f"Instruction reçue de Hive: {instruction.type}")
            
            if instruction.type == osiris_pb2.HiveInstruction.InstructionType.NOOP:
                # C'est normal, on continue
                pass
            elif instruction.type == osiris_pb2.HiveInstruction.InstructionType.EXECUTE_OQL:
                logging.info(f"Demande d'exécution OQL reçue: {instruction.payload}")
                # Ici, on lancera le moteur OQL (Phase 2)
                pass

    except grpc.RpcError as e:
        # La connexion a probablement été perdue
        logging.warning(f"Erreur RPC lors de la réception d'instructions: {e.details()}")
        raise e # Propage l'erreur pour déclencher la reconnexion

def run(config):
    """Démarre l'agent et sa boucle de communication/reconnexion."""
    agent_id = get_agent_id(config)
    logging.info(f"Démarrage de l'agent Osiris v{config['agent']['version']} avec l'ID: {agent_id}")
    
    # Charger les certificats pour mTLS
    try:
        with open(config['security']['ca_cert_path'], 'rb') as f:
            ca_cert = f.read()
        with open(config['security']['client_cert_path'], 'rb') as f:
            client_cert = f.read()
        with open(config['security']['client_key_path'], 'rb') as f:
            client_key = f.read()
    except FileNotFoundError as e:
        logging.critical(f"Erreur de certificat: {e}. Avez-vous exécuté 'scripts/generate_certs.py'?")
        return
        
    credentials = grpc.ssl_channel_credentials(
        root_certificates=ca_cert,
        private_key=client_key,
        certificate_chain=client_cert
    )
    
    hive_address = f"{config['hive']['host']}:{config['hive']['port']}"
    backoff_time = 5 # Temps d'attente initial en secondes

    while True:
        try:
            logging.info(f"Tentative de connexion à Hive sur {hive_address}...")
            with grpc.secure_channel(hive_address, credentials) as channel:
                stub = osiris_pb2_grpc.AgentCommsStub(channel)
                
                # Le générateur envoie le message d'enregistrement initial
                def request_generator():
                    yield initial_registration_message(agent_id, config)
                    # Le reste du temps, on attend juste
                    while True:
                        time.sleep(1)

                instruction_iterator = stub.Heartbeat(request_generator())
                logging.info("Connexion établie avec Hive. En attente d'instructions.")
                backoff_time = 5 # Réinitialiser le temps d'attente en cas de succès
                
                handle_hive_instructions(instruction_iterator)

        except grpc.RpcError as e:
            logging.error(f"Impossible de se connecter à Hive: {e.code()} - {e.details()}")
            logging.info(f"Nouvelle tentative dans {backoff_time} secondes...")
            time.sleep(backoff_time)
            backoff_time = min(backoff_time * 2, 300) # Augmenter le temps d'attente, max 5 minutes
        except Exception as e:
            logging.critical(f"Erreur fatale non gérée dans l'agent: {e}")
            break

if __name__ == '__main__':
    try:
        with open('agent/config.yaml', 'r') as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        print("[CRITICAL] Fichier de configuration 'agent/config.yaml' introuvable.")
        sys.exit(1)

    setup_logging(config)
    run(config) 