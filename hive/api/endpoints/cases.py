from fastapi import APIRouter, HTTPException, Depends
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/cases", tags=["cases"])

# Modèles Pydantic
class CaseBase(BaseModel):
    title: str
    description: Optional[str] = None
    priority: str = "medium"
    status: str = "open"
    tags: List[str] = []

class CaseCreate(CaseBase):
    pass

class Case(CaseBase):
    id: int
    created_at: datetime
    updated_at: datetime
    tenant_id: int

    class Config:
        from_attributes = True

class EvidenceBase(BaseModel):
    case_id: int
    type: str
    description: str
    data: dict

class EvidenceCreate(EvidenceBase):
    pass

class Evidence(EvidenceBase):
    id: int
    created_at: datetime
    tenant_id: int

    class Config:
        from_attributes = True

class CaseNoteBase(BaseModel):
    case_id: int
    content: str
    author: str

class CaseNoteCreate(CaseNoteBase):
    pass

class CaseNote(CaseNoteBase):
    id: int
    created_at: datetime
    tenant_id: int

    class Config:
        from_attributes = True

# Endpoints
@router.get("/", response_model=List[Case])
async def get_cases(
    skip: int = 0,
    limit: int = 100,
    status: Optional[str] = None,
    priority: Optional[str] = None
):
    """Récupère la liste des cas."""
    try:
        # Simulation de données
        cases = [
            {
                "id": 1,
                "title": "Suspicious Network Activity",
                "description": "Multiple failed login attempts detected",
                "priority": "high",
                "status": "open",
                "tags": ["network", "authentication"],
                "created_at": datetime.now(),
                "updated_at": datetime.now(),
                "tenant_id": 1
            },
            {
                "id": 2,
                "title": "Malware Detection",
                "description": "Suspicious executable found",
                "priority": "critical",
                "status": "investigating",
                "tags": ["malware", "executable"],
                "created_at": datetime.now(),
                "updated_at": datetime.now(),
                "tenant_id": 1
            }
        ]
        
        # Filtrer par statut si spécifié
        if status:
            cases = [case for case in cases if case["status"] == status]
        
        # Filtrer par priorité si spécifiée
        if priority:
            cases = [case for case in cases if case["priority"] == priority]
        
        return cases[skip:skip + limit]
    
    except Exception as e:
        logger.error(f"Error getting cases: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/", response_model=Case)
async def create_case(case: CaseCreate):
    """Crée un nouveau cas."""
    try:
        # Simulation de création
        new_case = {
            "id": 3,
            **case.dict(),
            "created_at": datetime.now(),
            "updated_at": datetime.now(),
            "tenant_id": 1
        }
        
        logger.info(f"Created new case: {new_case['title']}")
        return new_case
    
    except Exception as e:
        logger.error(f"Error creating case: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/{case_id}", response_model=Case)
async def get_case(case_id: int):
    """Récupère un cas spécifique."""
    try:
        # Simulation de récupération
        case = {
            "id": case_id,
            "title": f"Case {case_id}",
            "description": "Case description",
            "priority": "medium",
            "status": "open",
            "tags": [],
            "created_at": datetime.now(),
            "updated_at": datetime.now(),
            "tenant_id": 1
        }
        
        return case
    
    except Exception as e:
        logger.error(f"Error getting case {case_id}: {e}")
        raise HTTPException(status_code=404, detail="Case not found")

@router.put("/{case_id}", response_model=Case)
async def update_case(case_id: int, case: CaseCreate):
    """Met à jour un cas."""
    try:
        # Simulation de mise à jour
        updated_case = {
            "id": case_id,
            **case.dict(),
            "updated_at": datetime.now(),
            "created_at": datetime.now(),
            "tenant_id": 1
        }
        
        logger.info(f"Updated case {case_id}")
        return updated_case
    
    except Exception as e:
        logger.error(f"Error updating case {case_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.delete("/{case_id}")
async def delete_case(case_id: int):
    """Supprime un cas."""
    try:
        logger.info(f"Deleted case {case_id}")
        return {"message": f"Case {case_id} deleted successfully"}
    
    except Exception as e:
        logger.error(f"Error deleting case {case_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/{case_id}/evidence", response_model=List[Evidence])
async def get_case_evidence(case_id: int):
    """Récupère les preuves d'un cas."""
    try:
        # Simulation de preuves
        evidence = [
            {
                "id": 1,
                "case_id": case_id,
                "type": "network_log",
                "description": "Network connection logs",
                "data": {"connections": 150, "suspicious": 5},
                "created_at": datetime.now(),
                "tenant_id": 1
            }
        ]
        
        return evidence
    
    except Exception as e:
        logger.error(f"Error getting evidence for case {case_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/{case_id}/evidence", response_model=Evidence)
async def add_case_evidence(case_id: int, evidence: EvidenceCreate):
    """Ajoute une preuve à un cas."""
    try:
        # Simulation d'ajout de preuve
        new_evidence = {
            "id": 2,
            **evidence.dict(),
            "created_at": datetime.now(),
            "tenant_id": 1
        }
        
        logger.info(f"Added evidence to case {case_id}")
        return new_evidence
    
    except Exception as e:
        logger.error(f"Error adding evidence to case {case_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.get("/{case_id}/notes", response_model=List[CaseNote])
async def get_case_notes(case_id: int):
    """Récupère les notes d'un cas."""
    try:
        # Simulation de notes
        notes = [
            {
                "id": 1,
                "case_id": case_id,
                "content": "Initial investigation started",
                "author": "analyst1",
                "created_at": datetime.now(),
                "tenant_id": 1
            }
        ]
        
        return notes
    
    except Exception as e:
        logger.error(f"Error getting notes for case {case_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@router.post("/{case_id}/notes", response_model=CaseNote)
async def add_case_note(case_id: int, note: CaseNoteCreate):
    """Ajoute une note à un cas."""
    try:
        # Simulation d'ajout de note
        new_note = {
            "id": 2,
            **note.dict(),
            "created_at": datetime.now(),
            "tenant_id": 1
        }
        
        logger.info(f"Added note to case {case_id}")
        return new_note
    
    except Exception as e:
        logger.error(f"Error adding note to case {case_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error") 