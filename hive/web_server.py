from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi import Request
import uvicorn
import os
from typing import List, Dict, Any
import json
from datetime import datetime

app = FastAPI(title="Osiris Web Interface")

# Configuration des templates et fichiers statiques
templates = Jinja2Templates(directory="web/templates")
app.mount("/static", StaticFiles(directory="web/static"), name="static")

# Stockage en mémoire des agents connectés
connected_agents: Dict[str, Dict[str, Any]] = {}

def update_agent_status(agent_id: str, agent_info: Dict[str, Any]):
    """Met à jour les informations d'un agent."""
    connected_agents[agent_id] = {
        **agent_info,
        "last_seen": datetime.now().isoformat()
    }

def remove_agent(agent_id: str):
    """Supprime un agent de la liste des agents connectés."""
    if agent_id in connected_agents:
        del connected_agents[agent_id]

@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """Sert la page d'accueil."""
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/api/agents")
async def list_agents() -> List[Dict[str, Any]]:
    """Retourne la liste des agents connectés."""
    return list(connected_agents.values())

@app.post("/api/submit_query")
async def submit_query(agent_id: str, query_string: str) -> Dict[str, Any]:
    """Soumet une requête OQL à un agent spécifique."""
    if agent_id not in connected_agents:
        raise HTTPException(status_code=404, detail="Agent non trouvé")
    
    # TODO: Implémenter la logique de soumission de requête
    # Pour l'instant, on simule une réponse
    return {
        "query_id": "q_" + datetime.now().strftime("%Y%m%d%H%M%S"),
        "status": "submitted",
        "agent_id": agent_id,
        "query": query_string
    }

def start_web_server(host: str = "0.0.0.0", port: int = 8000):
    """Démarre le serveur web FastAPI."""
    uvicorn.run(app, host=host, port=port) 