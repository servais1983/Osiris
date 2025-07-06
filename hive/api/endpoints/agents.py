from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

router = APIRouter()

@router.post("/agents/{agent_id}/actions/{action_name}")
async def trigger_agent_action(
    agent_id: str, 
    action_name: str, 
    parameters: Optional[Dict[str, Any]] = None,
    background_tasks: BackgroundTasks = None
):
    """
    Déclenche une action de réponse sur un agent spécifique.
    
    Actions supportées:
    - isolate: Isole l'hôte du réseau
    - deisolate: Restaure la connectivité réseau
    - kill_process: Tue un processus spécifique
    - delete_file: Supprime un fichier
    """
    
    # Validation des actions supportées
    supported_actions = ["isolate", "deisolate", "kill_process", "delete_file"]
    if action_name not in supported_actions:
        raise HTTPException(
            status_code=400, 
            detail=f"Action '{action_name}' not supported. Supported actions: {supported_actions}"
        )

    try:
        # 1. Retrouver la connexion gRPC active pour cet agent_id
        # active_grpc_connection = get_grpc_connection(agent_id)
        # if not active_grpc_connection:
        #     raise HTTPException(status_code=404, detail="Agent not connected")

        # 2. Valider les paramètres selon l'action
        validated_params = validate_action_parameters(action_name, parameters or {})
        
        # 3. Envoyer la requête d'action via gRPC
        # grpc_request = ActionRequest(
        #     action_name=action_name,
        #     parameters=validated_params,
        #     request_id=generate_request_id(),
        #     timestamp=int(time.time())
        # )
        # grpc_response = await active_grpc_connection.ExecuteAction(grpc_request)

        logger.info(f"Triggering action '{action_name}' on agent '{agent_id}' with params: {validated_params}")
        
        # Simulation de la réponse gRPC
        mock_success = True
        mock_message = f"Action '{action_name}' executed successfully on agent {agent_id}"
        
        if not mock_success:
            raise HTTPException(status_code=500, detail=mock_message)
        
        # 4. Enregistrer l'action dans l'historique
        if background_tasks:
            background_tasks.add_task(log_action_execution, agent_id, action_name, validated_params)
        
        return {
            "status": "success", 
            "message": mock_message,
            "agent_id": agent_id,
            "action": action_name,
            "parameters": validated_params
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error executing action '{action_name}' on agent '{agent_id}': {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.get("/agents/{agent_id}/actions/{action_name}/status")
async def get_action_status(agent_id: str, action_name: str, request_id: str):
    """
    Récupère le statut d'une action en cours ou terminée.
    """
    try:
        # active_grpc_connection = get_grpc_connection(agent_id)
        # if not active_grpc_connection:
        #     raise HTTPException(status_code=404, detail="Agent not connected")
        
        # grpc_request = ActionStatusRequest(
        #     action_name=action_name,
        #     request_id=request_id
        # )
        # grpc_response = await active_grpc_connection.GetActionStatus(grpc_request)
        
        # Simulation du statut
        mock_status = {
            "status": "completed",
            "message": f"Action '{action_name}' completed successfully",
            "start_time": 1642234567,
            "end_time": 1642234568,
            "results": {"execution_time": "1s"}
        }
        
        return mock_status
        
    except Exception as e:
        logger.error(f"Error getting status for action '{action_name}' on agent '{agent_id}': {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.get("/agents/{agent_id}/actions")
async def list_agent_actions(agent_id: str):
    """
    Liste les actions disponibles pour un agent.
    """
    try:
        # Vérifier que l'agent existe et est connecté
        # agent = get_agent(agent_id)
        # if not agent:
        #     raise HTTPException(status_code=404, detail="Agent not found")
        
        # Retourner les actions supportées selon la plateforme de l'agent
        actions = {
            "isolate": {
                "name": "Isolate Host",
                "description": "Isoler l'hôte du réseau en bloquant tout le trafic sauf vers le Hive",
                "parameters": {},
                "requires_confirmation": True,
                "danger_level": "high"
            },
            "deisolate": {
                "name": "Restore Connectivity",
                "description": "Restaurer la connectivité réseau",
                "parameters": {},
                "requires_confirmation": False,
                "danger_level": "low"
            },
            "kill_process": {
                "name": "Kill Process",
                "description": "Terminer un processus spécifique",
                "parameters": {
                    "process_name": "string",
                    "process_id": "integer (optional)"
                },
                "requires_confirmation": True,
                "danger_level": "medium"
            },
            "delete_file": {
                "name": "Delete File",
                "description": "Supprimer un fichier du système",
                "parameters": {
                    "file_path": "string"
                },
                "requires_confirmation": True,
                "danger_level": "high"
            }
        }
        
        return {
            "agent_id": agent_id,
            "available_actions": actions
        }
        
    except Exception as e:
        logger.error(f"Error listing actions for agent '{agent_id}': {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

def validate_action_parameters(action_name: str, parameters: Dict[str, Any]) -> Dict[str, str]:
    """
    Valide les paramètres selon l'action demandée.
    """
    validated = {}
    
    if action_name == "isolate":
        # Pas de paramètres requis pour l'isolation
        pass
    elif action_name == "deisolate":
        # Pas de paramètres requis pour la désisolation
        pass
    elif action_name == "kill_process":
        if "process_name" not in parameters and "process_id" not in parameters:
            raise HTTPException(
                status_code=400, 
                detail="Either 'process_name' or 'process_id' must be provided for kill_process action"
            )
        if "process_name" in parameters:
            validated["process_name"] = str(parameters["process_name"])
        if "process_id" in parameters:
            validated["process_id"] = str(parameters["process_id"])
    elif action_name == "delete_file":
        if "file_path" not in parameters:
            raise HTTPException(
                status_code=400, 
                detail="'file_path' parameter is required for delete_file action"
            )
        validated["file_path"] = str(parameters["file_path"])
    
    return validated

def log_action_execution(agent_id: str, action_name: str, parameters: Dict[str, Any]):
    """
    Enregistre l'exécution d'une action dans les logs.
    """
    logger.info(f"Action executed - Agent: {agent_id}, Action: {action_name}, Parameters: {parameters}")
    # TODO: Enregistrer dans la base de données pour audit trail

def generate_request_id() -> str:
    """
    Génère un ID unique pour tracer les requêtes.
    """
    import time
    import uuid
    return f"req_{int(time.time())}_{str(uuid.uuid4())[:8]}" 