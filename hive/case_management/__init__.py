from datetime import datetime
from typing import Dict, List, Any, Optional
from uuid import uuid4
import json

class Case:
    """Représente un cas d'investigation"""
    
    def __init__(self, title: str, description: str, created_by: str):
        self.id = str(uuid4())
        self.title = title
        self.description = description
        self.created_by = created_by
        self.created_at = datetime.utcnow()
        self.updated_at = self.created_at
        self.status = 'open'
        self.tags = []
        self.queries = []
        self.results = []
        self.notes = []
        self.alerts = []
    
    def to_dict(self) -> Dict[str, Any]:
        """Convertit le cas en dictionnaire"""
        return {
            'id': self.id,
            'title': self.title,
            'description': self.description,
            'created_by': self.created_by,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat(),
            'status': self.status,
            'tags': self.tags,
            'queries': self.queries,
            'results': self.results,
            'notes': self.notes,
            'alerts': self.alerts
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Case':
        """Crée un cas à partir d'un dictionnaire"""
        case = cls(
            title=data['title'],
            description=data['description'],
            created_by=data['created_by']
        )
        case.id = data['id']
        case.created_at = datetime.fromisoformat(data['created_at'])
        case.updated_at = datetime.fromisoformat(data['updated_at'])
        case.status = data['status']
        case.tags = data['tags']
        case.queries = data['queries']
        case.results = data['results']
        case.notes = data['notes']
        case.alerts = data['alerts']
        return case

class CaseManager:
    """Gestionnaire des cas d'investigation"""
    
    def __init__(self, storage_backend):
        self.storage = storage_backend
    
    async def create_case(self, title: str, description: str, created_by: str) -> Case:
        """Crée un nouveau cas"""
        case = Case(title, description, created_by)
        await self.storage.insert_batch('cases', [case.to_dict()])
        return case
    
    async def get_case(self, case_id: str) -> Optional[Case]:
        """Récupère un cas par son ID"""
        result = await self.storage.execute_query(
            "SELECT * FROM cases WHERE id = $1",
            {'id': case_id}
        )
        if result:
            return Case.from_dict(result[0])
        return None
    
    async def update_case(self, case: Case) -> None:
        """Met à jour un cas"""
        case.updated_at = datetime.utcnow()
        await self.storage.execute_query(
            """
            UPDATE cases 
            SET title = $1, description = $2, status = $3, 
                tags = $4, updated_at = $5
            WHERE id = $6
            """,
            {
                'title': case.title,
                'description': case.description,
                'status': case.status,
                'tags': case.tags,
                'updated_at': case.updated_at,
                'id': case.id
            }
        )
    
    async def add_note(self, case_id: str, content: str, author: str) -> None:
        """Ajoute une note à un cas"""
        note = {
            'id': str(uuid4()),
            'case_id': case_id,
            'content': content,
            'author': author,
            'created_at': datetime.utcnow().isoformat()
        }
        await self.storage.insert_batch('case_notes', [note])
    
    async def add_query(self, case_id: str, query: str, description: str) -> None:
        """Ajoute une requête à un cas"""
        query_data = {
            'id': str(uuid4()),
            'case_id': case_id,
            'query': query,
            'description': description,
            'created_at': datetime.utcnow().isoformat()
        }
        await self.storage.insert_batch('case_queries', [query_data])
    
    async def add_result(self, case_id: str, query_id: str, result: Dict[str, Any]) -> None:
        """Ajoute un résultat à un cas"""
        result_data = {
            'id': str(uuid4()),
            'case_id': case_id,
            'query_id': query_id,
            'result': json.dumps(result),
            'created_at': datetime.utcnow().isoformat()
        }
        await self.storage.insert_batch('case_results', [result_data])
    
    async def add_alert(self, case_id: str, alert: Dict[str, Any]) -> None:
        """Ajoute une alerte à un cas"""
        alert_data = {
            'id': str(uuid4()),
            'case_id': case_id,
            'alert_data': json.dumps(alert),
            'created_at': datetime.utcnow().isoformat()
        }
        await self.storage.insert_batch('case_alerts', [alert_data])
    
    async def search_cases(self, query: str) -> List[Case]:
        """Recherche des cas"""
        results = await self.storage.execute_query(
            """
            SELECT * FROM cases 
            WHERE title ILIKE $1 
               OR description ILIKE $1 
               OR $1 = ANY(tags)
            ORDER BY updated_at DESC
            """,
            {'query': f'%{query}%'}
        )
        return [Case.from_dict(r) for r in results] 