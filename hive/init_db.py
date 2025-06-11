from database import init_db, SessionLocal, Case, Query, Agent, Alert, TimelineEvent, User
from datetime import datetime, timedelta
import uuid
import yaml
import os

def load_config():
    config_path = os.path.join(os.path.dirname(__file__), "config.yaml")
    with open(config_path, "r") as f:
        return yaml.safe_load(f)

def create_test_data():
    db = SessionLocal()
    try:
        # Création d'un cas de test
        case = Case(
            id=f"case_{uuid.uuid4().hex[:8]}",
            name="Test Investigation",
            description="Cas de test pour la démonstration",
            created_at=datetime.utcnow(),
            status="active",
            tags=["test", "demo"]
        )
        db.add(case)
        db.commit()
        db.refresh(case)

        # Création d'un agent de test
        agent = Agent(
            id=f"agent_{uuid.uuid4().hex[:8]}",
            name="Test Agent",
            platform="Windows",
            version="1.0.0",
            status="online",
            last_seen=datetime.utcnow(),
            capabilities=["process_collection", "network_collection", "log_collection"]
        )
        db.add(agent)
        db.commit()
        db.refresh(agent)

        # Création d'une requête de test
        query = Query(
            id=f"q_{uuid.uuid4().hex[:8]}",
            case_id=case.id,
            query_string="SELECT * FROM processes WHERE name = 'explorer.exe'",
            status="completed",
            created_at=datetime.utcnow(),
            results={"processes": [{"name": "explorer.exe", "pid": 1234}]}
        )
        db.add(query)
        db.commit()
        db.refresh(query)

        # Création d'une alerte de test
        alert = Alert(
            id=f"alert_{uuid.uuid4().hex[:8]}",
            case_id=case.id,
            severity="high",
            title="Processus suspect détecté",
            description="Un processus suspect a été détecté sur le système",
            created_at=datetime.utcnow(),
            status="new",
            alert_data={"process_name": "suspicious.exe", "pid": 5678}
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)

        # Création d'un événement de timeline
        event = TimelineEvent(
            id=f"event_{uuid.uuid4().hex[:8]}",
            case_id=case.id,
            timestamp=datetime.utcnow(),
            event_type="process_creation",
            source="windows",
            data={"process_name": "explorer.exe", "pid": 1234},
            tags=["process", "system"]
        )
        db.add(event)
        db.commit()
        db.refresh(event)

        # Création d'un utilisateur de test
        user = User(
            id=f"user_{uuid.uuid4().hex[:8]}",
            username="admin",
            email="admin@example.com",
            hashed_password="hashed_password_here",  # À changer en production
            is_active=True,
            is_admin=True,
            created_at=datetime.utcnow()
        )
        db.add(user)
        db.commit()
        db.refresh(user)

    except Exception as e:
        print(f"Erreur lors de la création des données de test : {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    print("Initialisation de la base de données...")
    init_db()
    print("Création des données de test...")
    create_test_data()
    print("Terminé !") 