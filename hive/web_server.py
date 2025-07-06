from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi import Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
import uvicorn
import os
from typing import List, Dict, Any, Optional
import json
from datetime import datetime, timedelta
import asyncio
from pydantic import BaseModel
import jwt
from pathlib import Path
from sqlalchemy.orm import Session
from . import database
from .database import get_db, Case as DBCase, Query as DBQuery, Agent as DBAgent, Alert as DBAlert, TimelineEvent as DBTimelineEvent
from fastapi.middleware.cors import CORSMiddleware

# Import des endpoints de gestion de cas
try:
    from .api.endpoints.cases import router as cases_router
except ImportError:
    # Fallback si le module n'existe pas encore
    cases_router = None

# Modèles Pydantic pour la validation des données
class CaseBase(BaseModel):
    name: str
    description: str
    tags: List[str] = []

class CaseCreate(CaseBase):
    pass

class Case(CaseBase):
    id: str
    created_at: datetime
    status: str

    class Config:
        orm_mode = True

class QueryBase(BaseModel):
    query_string: str
    case_id: str

class QueryCreate(QueryBase):
    pass

class Query(QueryBase):
    id: str
    status: str
    created_at: datetime
    results: Optional[Dict[str, Any]]

    class Config:
        orm_mode = True

class AgentBase(BaseModel):
    name: str
    platform: str
    version: str
    capabilities: List[str]

class AgentCreate(AgentBase):
    pass

class Agent(AgentBase):
    id: str
    status: str
    last_seen: datetime

    class Config:
        orm_mode = True

# Configuration
SECRET_KEY = os.getenv("OSIRIS_SECRET_KEY", "your-secret-key-here")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

app = FastAPI(title="Osiris DFIR Platform")

# Configuration des templates et fichiers statiques
templates = Jinja2Templates(directory="web/templates")
app.mount("/static", StaticFiles(directory="web/static"), name="static")

# Sécurité
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Configuration CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # En production, spécifier les domaines autorisés
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Inclusion des routes de gestion de cas
if cases_router:
    app.include_router(cases_router, prefix="/api/v1", tags=["cases"])

# Endpoints d'authentification
@app.post("/api/auth/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # TODO: Implémenter la vérification des identifiants
    access_token = create_access_token(data={"sub": form_data.username})
    return {"access_token": access_token, "token_type": "bearer"}

# Endpoints des cas
@app.get("/api/cases", response_model=List[Case])
async def list_cases(db: Session = Depends(get_db)):
    return db.query(DBCase).all()

@app.post("/api/cases", response_model=Case)
async def create_case(case: CaseCreate, db: Session = Depends(get_db)):
    db_case = DBCase(
        id=f"case_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        name=case.name,
        description=case.description,
        tags=case.tags
    )
    db.add(db_case)
    db.commit()
    db.refresh(db_case)
    return db_case

@app.get("/api/cases/{case_id}", response_model=Case)
async def get_case(case_id: str, db: Session = Depends(get_db)):
    case = db.query(DBCase).filter(DBCase.id == case_id).first()
    if not case:
        raise HTTPException(status_code=404, detail="Cas non trouvé")
    return case

# Endpoints des requêtes
@app.get("/api/queries", response_model=List[Query])
async def list_queries(case_id: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(DBQuery)
    if case_id:
        query = query.filter(DBQuery.case_id == case_id)
    return query.all()

@app.post("/api/queries", response_model=Query)
async def create_query(query: QueryCreate, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    db_query = DBQuery(
        id=f"q_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        query_string=query.query_string,
        case_id=query.case_id
    )
    db.add(db_query)
    db.commit()
    db.refresh(db_query)
    background_tasks.add_task(execute_query, db_query.id, db)
    return db_query

# Endpoints des agents
@app.get("/api/agents", response_model=List[Agent])
async def list_agents(db: Session = Depends(get_db)):
    return db.query(DBAgent).all()

@app.post("/api/agents/{agent_id}/query")
async def submit_agent_query(agent_id: str, query: QueryCreate, db: Session = Depends(get_db)):
    agent = db.query(DBAgent).filter(DBAgent.id == agent_id).first()
    if not agent:
        raise HTTPException(status_code=404, detail="Agent non trouvé")
    
    db_query = DBQuery(
        id=f"q_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}",
        query_string=query.query_string,
        case_id=query.case_id
    )
    db.add(db_query)
    db.commit()
    db.refresh(db_query)
    
    # TODO: Implémenter la logique de soumission de requête à l'agent
    return {"status": "submitted", "query_id": db_query.id}

# Endpoints de l'historique
@app.get("/api/history")
async def get_history(case_id: Optional[str] = None, limit: int = 100, db: Session = Depends(get_db)):
    query = db.query(DBTimelineEvent)
    if case_id:
        query = query.filter(DBTimelineEvent.case_id == case_id)
    return query.order_by(DBTimelineEvent.timestamp.desc()).limit(limit).all()

# Endpoints de la timeline
@app.get("/api/timeline")
async def get_timeline(case_id: str, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None, db: Session = Depends(get_db)):
    query = db.query(DBTimelineEvent).filter(DBTimelineEvent.case_id == case_id)
    if start_time:
        query = query.filter(DBTimelineEvent.timestamp >= start_time)
    if end_time:
        query = query.filter(DBTimelineEvent.timestamp <= end_time)
    return query.order_by(DBTimelineEvent.timestamp).all()

# Endpoints des alertes
@app.get("/api/alerts")
async def get_alerts(case_id: Optional[str] = None, severity: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(DBAlert)
    if case_id:
        query = query.filter(DBAlert.case_id == case_id)
    if severity:
        query = query.filter(DBAlert.severity == severity)
    return query.order_by(DBAlert.created_at.desc()).all()

# Routes web
@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/cases", response_class=HTMLResponse)
async def cases_page(request: Request):
    return templates.TemplateResponse("cases.html", {"request": request})

@app.get("/timeline", response_class=HTMLResponse)
async def timeline_page(request: Request):
    return templates.TemplateResponse("timeline.html", {"request": request})

@app.get("/alerts", response_class=HTMLResponse)
async def alerts_page(request: Request):
    return templates.TemplateResponse("alerts.html", {"request": request})

@app.get("/investigation", response_class=HTMLResponse)
async def investigation_page(request: Request):
    return templates.TemplateResponse("investigation.html", {"request": request})

# Fonctions utilitaires
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def execute_query(query_id: str, db: Session):
    # TODO: Implémenter l'exécution de la requête
    await asyncio.sleep(1)  # Simulation d'une requête longue
    query = db.query(DBQuery).filter(DBQuery.id == query_id).first()
    if query:
        query.status = "completed"
        query.results = {"message": "Résultats simulés"}
        db.commit()

def start_web_server(host: str = "0.0.0.0", port: int = 8002):
    """Démarre le serveur web FastAPI."""
    uvicorn.run(app, host=host, port=port)

if __name__ == "__main__":
    start_web_server() 