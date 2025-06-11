import os
import sys
import ssl
import uuid
import logging
import threading
import grpc
import time
import yaml
from datetime import datetime, timezone
from itertools import cycle
from pathlib import Path
from typing import Dict, Optional, List, Any
from concurrent import futures
from dotenv import load_dotenv
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from hive.web_server import start_web_server, update_agent_status, remove_agent
import asyncio
import uvicorn
from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from hive.database import Database
from hive.timeline_normalizer import TimelineNormalizer
from hive.ai.analyzer import AIAnalyzer
from hive.ai.assistant import AIAssistant
from hive.detectors.sigma_detector import SigmaDetector
from hive.enrichers.virustotal import VirusTotalEnricher
import io
import csv
import json
from fastapi.responses import StreamingResponse
from hive.ai import AlertAnalyzer

# Ajouter le répertoire parent au PYTHONPATH
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import des modules proto
from protos import osiris_pb2
from protos import osiris_pb2_grpc

# Charger les variables d'environnement
load_dotenv()

# Configuration du logging
logger = logging.getLogger(__name__)

# Configuration pour trouver les fichiers .proto compilés
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../protos')))
import osiris_pb2
import osiris_pb2_grpc

# Configuration pour trouver les fichiers .proto et les modules locaux
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../protos')))
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '.')))

import osiris_pb2
import osiris_pb2_grpc

# Variables globales
AGENT_PORT = int(os.getenv('AGENT_PORT', '50051'))
HIVE_CERT_PATH = os.getenv('HIVE_CERT_PATH', 'certs/hive.crt')
HIVE_KEY_PATH = os.getenv('HIVE_KEY_PATH', 'certs/hive.key')
AGENT_CERT_PATH = os.getenv('AGENT_CERT_PATH', 'certs/agent.crt')

# Chargement des certificats
def load_pem_certificate(path):
    with open(path, 'rb') as f:
        return f.read()

def load_pem_private_key(path):
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(
            f.read(),
            password=None
        )

# Configuration SSL
ssl_credentials = grpc.ssl_server_credentials(
    [(load_pem_private_key(HIVE_KEY_PATH), load_pem_certificate(HIVE_CERT_PATH))],
    root_certificates=load_pem_certificate(AGENT_CERT_PATH),
    require_client_auth=True
)

# --- Initialisation Globale ---
CONFIG = None
VT_ENRICHER = None
connected_agents: Dict[str, Dict] = {}
agent_lock = threading.Lock()

# --- Gestionnaires de connexions et de données ---
class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, query_id: str):
        await websocket.accept()
        if query_id not in self.active_connections:
            self.active_connections[query_id] = []
        self.active_connections[query_id].append(websocket)
        logger.info(f"WebSocket connecté pour query_id: {query_id}")

    def disconnect(self, websocket: WebSocket, query_id: str):
        if query_id in self.active_connections:
            self.active_connections[query_id].remove(websocket)
            if not self.active_connections[query_id]:
                del self.active_connections[query_id]
            logger.info(f"WebSocket déconnecté pour query_id: {query_id}")

    async def broadcast(self, query_id: str, message: dict):
        if query_id in self.active_connections:
            for connection in self.active_connections[query_id]:
                try:
                    await connection.send_json(message)
                except WebSocketDisconnect:
                    self.disconnect(connection, query_id)

manager = ConnectionManager()

# --- Serveur API (FastAPI) ---
api_app = FastAPI(title="Osiris Hive")

# Configuration CORS
api_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Montage des fichiers statiques
api_app.mount("/static", StaticFiles(directory="web/static"), name="static")
templates = Jinja2Templates(directory="web/templates")

class QueryRequest(BaseModel):
    agent_id: str
    query_string: str

class AgentInfo(BaseModel):
    agent_id: str
    hostname: str
    ip_address: str = None
    os_info: str = None

@api_app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@api_app.get("/cases", response_class=HTMLResponse)
async def cases_page(request: Request):
    return templates.TemplateResponse("cases.html", {"request": request})

@api_app.get("/api/agents")
async def get_agents():
    with agent_lock:
        agents_list = []
        for agent_id, data in connected_agents.items():
            agent_data = data.copy()
            agent_data['last_seen'] = agent_data['last_seen'].isoformat()
            agent_data['id'] = agent_id
            agents_list.append(agent_data)
        return agents_list

@api_app.post("/api/query")
async def submit_query(query: QueryRequest):
    try:
        query_id = str(uuid.uuid4())
        add_query_to_history(query_id, query.agent_id, query.query_string)
        
        # TODO: Implémenter la logique d'envoi de la requête à l'agent
        # Pour l'instant, on simule une réponse
        update_query_status(query_id, "completed")
        
        return {"query_id": query_id, "status": "submitted"}
    except Exception as e:
        logger.error(f"Erreur lors de la soumission de la requête: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@api_app.get("/api/history")
async def get_history():
    try:
        queries = get_all_queries()
        return {"queries": queries}
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de l'historique: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@api_app.get("/api/results/{query_id}")
async def get_results(query_id: str):
    try:
        results = get_results_for_query(query_id)
        return {"results": results}
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des résultats: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@api_app.get("/api/timeline/{agent_id}")
async def get_timeline(agent_id: str):
    try:
        # Récupérer les résultats bruts
        raw_results = get_agent_timeline(agent_id)
        
        # Normaliser en timeline
        timeline = normalize_results_to_timeline(raw_results)
        
        # Vérifier chaque événement avec Sigma
        sigma_rules_path = os.getenv("SIGMA_RULES_PATH", "rules/sigma")
        sigma_detector = SigmaDetector(sigma_rules_path)
        for event in timeline:
            matching_rules = sigma_detector.check(event)
            if matching_rules:
                event['sigma_matches'] = [
                    sigma_detector.get_rule_details(rule)
                    for rule in matching_rules
                ]
        
        return {"timeline": timeline}
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de la timeline: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@api_app.websocket("/api/ws/results/{query_id}")
async def websocket_endpoint(websocket: WebSocket, query_id: str):
    await manager.connect(websocket, query_id)
    try:
        while True:
            # On garde la connexion active
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket, query_id)

@api_app.get("/api/cases")
async def get_cases():
    try:
        cases = get_all_cases()
        return {"cases": cases}
    except Exception as e:
        logging.error(f"Erreur lors de la récupération des cas: {e}")
        raise HTTPException(status_code=500, detail="Erreur lors de la récupération des cas")

@api_app.post("/api/cases")
async def create_new_case(case: Dict[str, Any]):
    try:
        case_id = create_case(
            title=case["title"],
            description=case.get("description", ""),
            priority=case.get("priority", "medium")
        )
        return {"id": case_id}
    except Exception as e:
        logging.error(f"Erreur lors de la création du cas: {e}")
        raise HTTPException(status_code=500, detail="Erreur lors de la création du cas")

@api_app.get("/api/cases/{case_id}")
async def get_case_details(case_id: int):
    try:
        case = get_case(case_id)
        if not case:
            raise HTTPException(status_code=404, detail="Cas non trouvé")
        return case
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Erreur lors de la récupération du cas: {e}")
        raise HTTPException(status_code=500, detail="Erreur lors de la récupération du cas")

@api_app.put("/api/cases/{case_id}/status")
async def update_case_status_endpoint(case_id: int, status: Dict[str, str]):
    try:
        update_case_status(case_id, status["status"])
        return {"message": "Statut mis à jour avec succès"}
    except Exception as e:
        logging.error(f"Erreur lors de la mise à jour du statut: {e}")
        raise HTTPException(status_code=500, detail="Erreur lors de la mise à jour du statut")

@api_app.get("/api/cases/{case_id}/agents")
async def get_case_agents_endpoint(case_id: int):
    try:
        agents = get_case_agents(case_id)
        return {"agents": agents}
    except Exception as e:
        logging.error(f"Erreur lors de la récupération des agents: {e}")
        raise HTTPException(status_code=500, detail="Erreur lors de la récupération des agents")

@api_app.get("/api/cases/{case_id}/queries")
async def get_case_queries_endpoint(case_id: int):
    try:
        queries = get_case_queries(case_id)
        return {"queries": queries}
    except Exception as e:
        logging.error(f"Erreur lors de la récupération des requêtes: {e}")
        raise HTTPException(status_code=500, detail="Erreur lors de la récupération des requêtes")

@api_app.get("/api/cases/{case_id}/alerts")
async def get_case_alerts_endpoint(case_id: int):
    try:
        alerts = get_case_alerts(case_id)
        return {"alerts": alerts}
    except Exception as e:
        logging.error(f"Erreur lors de la récupération des alertes: {e}")
        raise HTTPException(status_code=500, detail="Erreur lors de la récupération des alertes")

@api_app.get("/api/cases/{case_id}/notes")
async def get_case_notes_endpoint(case_id: int):
    try:
        notes = get_case_notes(case_id)
        return {"notes": notes}
    except Exception as e:
        logging.error(f"Erreur lors de la récupération des notes: {e}")
        raise HTTPException(status_code=500, detail="Erreur lors de la récupération des notes")

@api_app.post("/api/cases/{case_id}/notes")
async def add_note_endpoint(case_id: int, note: Dict[str, str]):
    try:
        note_id = add_note_to_case(
            case_id=case_id,
            content=note["content"],
            author=note["author"]
        )
        return {"id": note_id}
    except Exception as e:
        logging.error(f"Erreur lors de l'ajout de la note: {e}")
        raise HTTPException(status_code=500, detail="Erreur lors de l'ajout de la note")

@api_app.post("/api/cases/{case_id}/agents")
async def add_agent_endpoint(case_id: int, agent: Dict[str, str]):
    try:
        success = add_agent_to_case(case_id, agent["agent_id"])
        if not success:
            raise HTTPException(status_code=400, detail="L'agent est déjà associé à ce cas")
        return {"message": "Agent ajouté avec succès"}
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Erreur lors de l'ajout de l'agent: {e}")
        raise HTTPException(status_code=500, detail="Erreur lors de l'ajout de l'agent")

@api_app.post("/api/cases/{case_id}/queries")
async def add_query_endpoint(case_id: int, query: Dict[str, int]):
    try:
        success = add_query_to_case(case_id, query["query_id"])
        if not success:
            raise HTTPException(status_code=400, detail="La requête est déjà associée à ce cas")
        return {"message": "Requête ajoutée avec succès"}
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Erreur lors de l'ajout de la requête: {e}")
        raise HTTPException(status_code=500, detail="Erreur lors de l'ajout de la requête")

@api_app.post("/api/cases/{case_id}/alerts")
async def add_alert_endpoint(case_id: int, alert: Dict[str, int]):
    try:
        success = add_alert_to_case(case_id, alert["alert_id"])
        if not success:
            raise HTTPException(status_code=400, detail="L'alerte est déjà associée à ce cas")
        return {"message": "Alerte ajoutée avec succès"}
    except HTTPException:
        raise
    except Exception as e:
        logging.error(f"Erreur lors de l'ajout de l'alerte: {e}")
        raise HTTPException(status_code=500, detail="Erreur lors de l'ajout de l'alerte")

@api_app.get("/api/alerts")
async def get_alerts(
    status: str = None,
    level: str = None,
    case_id: int = None,
    limit: int = 100,
    offset: int = 0
):
    """Récupère la liste des alertes avec filtres optionnels."""
    try:
        alerts = database.get_alerts(
            status=status,
            level=level,
            case_id=case_id,
            limit=limit,
            offset=offset
        )
        return alerts
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des alertes: {str(e)}")
        raise HTTPException(status_code=500, detail="Erreur lors de la récupération des alertes")

@api_app.get("/api/alerts/{alert_id}")
async def get_alert(alert_id: int):
    """Récupère les détails d'une alerte spécifique."""
    try:
        alert = database.get_alert(alert_id)
        if not alert:
            raise HTTPException(status_code=404, detail="Alerte non trouvée")
        return alert
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de l'alerte {alert_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Erreur lors de la récupération de l'alerte")

@api_app.put("/api/alerts/{alert_id}")
async def update_alert(alert_id: int, alert_data: dict):
    """Met à jour le statut d'une alerte."""
    try:
        success = database.update_alert_status(
            alert_id=alert_id,
            status=alert_data.get("status"),
            case_id=alert_data.get("case_id")
        )
        if not success:
            raise HTTPException(status_code=404, detail="Alerte non trouvée")
        return {"message": "Alerte mise à jour avec succès"}
    except Exception as e:
        logger.error(f"Erreur lors de la mise à jour de l'alerte {alert_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Erreur lors de la mise à jour de l'alerte")

@api_app.post("/api/alerts/{alert_id}/associate")
async def associate_alert_with_case(alert_id: int, data: dict):
    """Associe une alerte à un cas d'investigation."""
    try:
        success = database.associate_alert_with_case(
            alert_id=alert_id,
            case_id=data.get("case_id")
        )
        if not success:
            raise HTTPException(status_code=404, detail="Alerte non trouvée")
        return {"message": "Alerte associée au cas avec succès"}
    except Exception as e:
        logger.error(f"Erreur lors de l'association de l'alerte {alert_id}: {str(e)}")
        raise HTTPException(status_code=500, detail="Erreur lors de l'association de l'alerte")

@api_app.get("/api/alerts/export")
async def export_alerts(
    status: str = None,
    level: str = None,
    case_id: int = None
):
    """Exporte les alertes au format CSV."""
    try:
        alerts = database.get_alerts(
            status=status,
            level=level,
            case_id=case_id,
            limit=None,
            offset=0
        )
        
        # Création du fichier CSV
        output = io.StringIO()
        writer = csv.writer(output)
        
        # En-têtes
        writer.writerow([
            "ID", "Règle", "Niveau", "Statut", "Date de détection",
            "Cas associé", "Données de l'événement"
        ])
        
        # Données
        for alert in alerts:
            writer.writerow([
                alert["id"],
                alert["rule_title"],
                alert["rule_level"],
                alert["status"],
                alert["detected_at"],
                alert.get("case_id", ""),
                json.dumps(alert["event_data"])
            ])
        
        # Préparation de la réponse
        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename=alerts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            }
        )
    except Exception as e:
        logger.error(f"Erreur lors de l'export des alertes: {str(e)}")
        raise HTTPException(status_code=500, detail="Erreur lors de l'export des alertes")

# Initialisation de l'analyseur IA
alert_analyzer = AlertAnalyzer()

@api_app.post("/api/alerts/{alert_id}/analyze")
async def analyze_alert(alert_id: int):
    """Analyse une alerte avec l'IA."""
    try:
        # Récupération de l'alerte
        alert = database.get_alert(alert_id)
        if not alert:
            raise HTTPException(status_code=404, detail="Alerte non trouvée")
        
        # Analyse avec l'IA
        analysis = await alert_analyzer.analyze_alert(alert)
        
        if not analysis["success"]:
            raise HTTPException(
                status_code=500,
                detail=f"Erreur lors de l'analyse: {analysis['error']}"
            )
        
        return analysis["analysis"]
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse de l'alerte {alert_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Erreur lors de l'analyse de l'alerte"
        )

# Initialisation de l'assistant IA
ai_assistant = AIAssistant(
    api_key=os.getenv("GEMINI_API_KEY"),
    model="gemini-pro"
)

@api_app.post("/api/alerts/{alert_id}/analyze")
async def analyze_alert_with_assistant(alert_id: int):
    """Analyse une alerte avec l'assistant IA."""
    try:
        # Récupération de l'alerte
        alert = database.get_alert(alert_id)
        if not alert:
            raise HTTPException(status_code=404, detail="Alerte non trouvée")
        
        # Analyse avec l'IA
        analysis = await ai_assistant.analyze_alert(alert)
        
        if not analysis["success"]:
            raise HTTPException(
                status_code=500,
                detail=f"Erreur lors de l'analyse: {analysis['error']}"
            )
        
        return analysis["analysis"]
    except Exception as e:
        logger.error(f"Erreur lors de l'analyse de l'alerte {alert_id}: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail="Erreur lors de l'analyse de l'alerte"
        )

@api_app.route("/api/translate_oql", methods=["POST"])
async def translate_oql():
    """Traduit une requête en langage naturel en OQL."""
    try:
        data = request.get_json()
        if not data or 'query' not in data:
            return jsonify({
                "success": False,
                "error": "Requête manquante"
            }), 400
        
        # Traduction avec l'IA
        result = await ai_assistant.translate_to_oql(data['query'])
        
        if not result["success"]:
            return jsonify({
                "success": False,
                "error": result["error"]
            }), 500
        
        # Logging de la traduction
        logger.info(f"Traduction OQL réussie: {data['query']} -> {result['query']}")
        
        # Ajout des métadonnées
        response = {
            "success": True,
            "query": result["query"],
            "metadata": {
                "tables_used": result["metadata"]["tables_used"],
                "complexity": result["metadata"]["estimated_complexity"],
                "optimizations": result["metadata"]["suggested_optimizations"],
                "timestamp": result["timestamp"]
            }
        }
        
        return jsonify(response)
        
    except Exception as e:
        logger.error(f"Erreur lors de la traduction OQL: {e}")
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500

# --- Serveur gRPC ---
class AgentCommsServicer(osiris_pb2_grpc.AgentCommsServicer):
    def Heartbeat(self, request_iterator, context):
        agent_id = None
        peer_address = context.peer()
        try:
            first_request = next(request_iterator)
            agent_id = first_request.agent_id
            with agent_lock:
                connected_agents[agent_id] = {"hostname": first_request.hostname, "os": first_request.os_type, "version": first_request.version, "ip": peer_address, "last_seen": datetime.now(timezone.utc), "instruction_queue": []}
            logging.info(f"Agent {agent_id} ({first_request.hostname}) enregistré depuis {peer_address}.")
            while context.is_active():
                instruction_to_send = None
                with agent_lock:
                    if agent_id in connected_agents and connected_agents[agent_id]["instruction_queue"]:
                        instruction_to_send = connected_agents[agent_id]["instruction_queue"].pop(0)
                if instruction_to_send:
                    yield instruction_to_send
                else:
                    yield osiris_pb2.HiveInstruction(type=osiris_pb2.HiveInstruction.InstructionType.NOOP)
                with agent_lock:
                    if agent_id in connected_agents:
                        connected_agents[agent_id]["last_seen"] = datetime.now(timezone.utc)
                time.sleep(5)
        except grpc.RpcError:
            logging.warning(f"Connexion perdue avec l'agent {agent_id or 'inconnu'} à {peer_address}.")
        finally:
            if agent_id and agent_id in connected_agents:
                with agent_lock: del connected_agents[agent_id]
                logging.info(f"Agent {agent_id} déconnecté.")

    def SendQueryResults(self, request_iterator, context):
        total_rows, query_id = 0, None
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            for result in request_iterator:
                if not query_id: query_id = result.query_id
                row_data = dict(result.row.items())
                
                if 'sha256' in row_data and VT_ENRICHER:
                    sha256_hash = row_data['sha256']
                    vt_detections = VT_ENRICHER.enrich(sha256_hash)
                    if vt_detections is not None:
                        row_data['vt_detections'] = vt_detections
                        if vt_detections > 0:
                            logging.warning(f"!!! ALERTE VIRUSTOTAL !!! Fichier {row_data.get('path')} (hash: {sha256_hash}) a {vt_detections} détections.")
                
                # Envoyer le résultat au client WebSocket correspondant
                message_to_send = {"type": "result", "data": row_data}
                loop.run_until_complete(manager.broadcast(query_id, message_to_send))
                
                logging.info(f"[{query_id}] Ligne reçue et poussée vers le WebSocket: {row_data}")
                total_rows += 1
            
            logging.info(f"[{query_id}] Réception des résultats terminée. Total de {total_rows} lignes.")
            summary_message = {"type": "summary", "data": {"message": "Collecte terminée", "total_rows": total_rows}}
            loop.run_until_complete(manager.broadcast(query_id, summary_message))
            
            return osiris_pb2.QuerySummary(query_id=query_id, received_successfully=True, row_count=total_rows, message="Résultats reçus avec succès.")
        except Exception as e:
            logging.error(f"[{query_id}] Erreur lors de la réception des résultats: {e}", exc_info=True)
            return osiris_pb2.QuerySummary(query_id=query_id, received_successfully=False)
        finally:
            loop.close()

def run_grpc_server(config):
    logging.info("Démarrage du serveur gRPC...")
    try:
        with open(config['security']['server_key_path'], 'rb') as f: private_key = f.read()
        with open(config['security']['server_cert_path'], 'rb') as f: certificate_chain = f.read()
        with open(config['security']['ca_cert_path'], 'rb') as f: ca_cert = f.read()
    except FileNotFoundError as e:
        logging.critical(f"Erreur de certificat gRPC: {e}.")
        return

    server_credentials = grpc.ssl_server_credentials([(private_key, certificate_chain)], root_certificates=ca_cert, require_client_auth=True)
    grpc_server = grpc.server(futures.ThreadPoolExecutor(max_workers=50))
    osiris_pb2_grpc.add_AgentCommsServicer_to_server(AgentCommsServicer(), grpc_server)
    grpc_port = config['server'].get('grpc_port', 50051)
    grpc_server.add_secure_port(f"[::]:{grpc_port}", server_credentials)
    grpc_server.start()
    logging.info(f"Serveur gRPC démarré sur le port {grpc_port}.")
    grpc_server.wait_for_termination()

def setup_logging(config):
    log_level = getattr(logging, config.get('logging', {}).get('level', 'INFO'))
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

def main():
    # Démarrage du serveur web dans un thread séparé
    import threading
    web_thread = threading.Thread(target=start_web_server)
    web_thread.daemon = True
    web_thread.start()
    
    # Démarrage du serveur gRPC
    asyncio.run(run_grpc_server(CONFIG))

if __name__ == '__main__':
    try:
        with open('hive/config.yaml', 'r') as f: CONFIG = yaml.safe_load(f)
    except FileNotFoundError:
        print("[CRITICAL] Fichier de configuration 'hive/config.yaml' introuvable.")
        sys.exit(1)
    
    setup_logging(CONFIG)
    VT_ENRICHER = VirusTotalEnricher(CONFIG.get('enrichment', {}).get('virustotal', {}).get('api_key'))
    
    grpc_thread = threading.Thread(target=run_grpc_server, args=(CONFIG,), daemon=True)
    grpc_thread.start()

    api_port = CONFIG['server'].get('api_port', 8000)
    logging.info(f"Démarrage du serveur API sur http://localhost:{api_port}")
    uvicorn.run(api_app, host="0.0.0.0", port=api_port) 