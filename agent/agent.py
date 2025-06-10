import os
import sys
import time
import logging
import threading
import grpc
import yaml
import uuid
import platform
import socket
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_certificate

# Configuration du logging
logger = logging.getLogger(__name__)

# Ajout du répertoire racine au PYTHONPATH
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import des messages proto
from protos import osiris_pb2
from protos import osiris_pb2_grpc
from agent.oql.runner import OQLRunner

def setup_logging(config):
    """Configure le logging selon les paramètres du fichier de configuration."""
    log_config = config.get('logging', {})
    log_level = getattr(logging, log_config.get('level', 'INFO'))
    log_format = log_config.get('format', '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    logging.basicConfig(
        level=log_level,
        format=log_format,
        handlers=[
            logging.StreamHandler(),
            logging.FileHandler(log_config.get('file', 'agent.log'))
        ]
    )
    logging.info("Logging configuré.")

class Agent:
    def __init__(self, config):
        self.config = config
        self.agent_id = str(uuid.uuid4())
        self.hostname = socket.gethostname()
        self.os_info = f"{platform.system()} {platform.release()}"
        self._load_certificates()
        self._setup_grpc_channel()
        self.oql_runner = OQLRunner()

    def _load_certificates(self):
        """Charge les certificats mTLS."""
        try:
            # Charger le certificat de l'agent
            with open(self.config['certs']['agent_cert'], 'rb') as f:
                self.agent_cert = load_pem_certificate(f.read())
            
            # Charger la clé privée de l'agent
            with open(self.config['certs']['agent_key'], 'rb') as f:
                self.agent_key = load_pem_private_key(
                    f.read(),
                    password=None
                )
            
            # Charger le certificat de la CA
            with open(self.config['certs']['ca_cert'], 'rb') as f:
                self.ca_cert = load_pem_certificate(f.read())
            
            logging.info("Certificats mTLS chargés avec succès.")
        except Exception as e:
            logging.error(f"Erreur lors du chargement des certificats: {e}")
            raise

    def _setup_grpc_channel(self):
        """Configure le canal gRPC avec mTLS."""
        try:
            # Créer les credentials mTLS
            credentials = grpc.ssl_channel_credentials(
                root_certificates=self.ca_cert.public_bytes(serialization.Encoding.PEM),
                private_key=self.agent_key.private_bytes(
                    serialization.Encoding.PEM,
                    serialization.PrivateFormat.PKCS8,
                    serialization.NoEncryption()
                ),
                certificate_chain=self.agent_cert.public_bytes(serialization.Encoding.PEM)
            )
            
            # Créer le canal gRPC
            self.channel = grpc.secure_channel(
                f"{self.config['hive']['host']}:{self.config['hive']['port']}",
                credentials
            )
            
            # Créer le stub
            self.stub = osiris_pb2_grpc.AgentCommsStub(self.channel)
            logging.info("Canal gRPC configuré avec succès.")
        except Exception as e:
            logging.error(f"Erreur lors de la configuration du canal gRPC: {e}")
            raise

    def register_with_hive(self):
        """Enregistre l'agent auprès du Hive."""
        try:
            request = osiris_pb2.RegistrationRequest(
                agent_id=self.agent_id,
                hostname=self.hostname,
                os_info=self.os_info
            )
            response = self.stub.Register(request)
            logging.info(f"Enregistrement réussi auprès du Hive. Status: {response.status}")
            return True
        except grpc.RpcError as e:
            logging.error(f"Erreur lors de l'enregistrement: {str(e)}")
            return False

    def handle_heartbeat(self, instruction):
        """Gère un heartbeat du Hive."""
        try:
            if instruction.HasField('query'):
                logging.info(f"Exécution de la requête: {instruction.query}")
                results = self.oql_runner.execute_query(instruction.query)
                
                # Envoyer les résultats au Hive
                for result in results:
                    query_result = osiris_pb2.QueryResult(
                        query_id=instruction.query_id,
                        result=result,
                        summary=osiris_pb2.QuerySummary(
                            query_id=instruction.query_id,
                            status="completed"
                        )
                    )
                    self.stub.SendQueryResults(query_result)
                
                # Envoyer le résumé final
                final_result = osiris_pb2.QueryResult(
                    query_id=instruction.query_id,
                    summary=osiris_pb2.QuerySummary(
                        query_id=instruction.query_id,
                        status="completed"
                    )
                )
                self.stub.SendQueryResults(final_result)
            
            return osiris_pb2.HeartbeatResponse(status="ok")
        except Exception as e:
            logging.error(f"Erreur lors du traitement du heartbeat: {e}")
            return osiris_pb2.HeartbeatResponse(status="error")

    def run(self):
        """Boucle principale de l'agent."""
        while True:
            try:
                if not self.register_with_hive():
                    logging.warning("Échec de l'enregistrement, nouvelle tentative dans 5 secondes...")
                    time.sleep(5)
                    continue

                # Boucle de heartbeat
                while True:
                    try:
                        response = self.stub.Heartbeat(osiris_pb2.HeartbeatRequest(agent_id=self.agent_id))
                        if response.HasField('instruction'):
                            self.handle_heartbeat(response.instruction)
                    except grpc.RpcError as e:
                        if e.code() == grpc.StatusCode.UNAVAILABLE:
                            logging.error(f"Le Hive est indisponible: {str(e)}")
                            break
                        else:
                            logging.error(f"Erreur de communication: {str(e)}")
                    
                    time.sleep(self.config['heartbeat']['interval'])

            except Exception as e:
                logging.error(f"Erreur dans la boucle principale: {e}")
                time.sleep(5)

if __name__ == '__main__':
    try:
        # Charger la configuration
        with open('config.yaml', 'r') as f:
            config = yaml.safe_load(f)
        
        # Configurer le logging
        setup_logging(config)
        
        # Créer et démarrer l'agent
        agent = Agent(config)
        agent.run()
    except Exception as e:
        logging.error(f"Erreur fatale: {e}", exc_info=True)
        sys.exit(1) 