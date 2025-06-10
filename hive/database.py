import sqlite3
import logging
import json
from typing import List, Dict, Any, Optional
from datetime import datetime
import os
from pathlib import Path

# Configuration du logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Chemin de la base de données
DB_PATH = Path("hive/data/osiris.db")
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

def initialize_database():
    """Initialise la base de données avec les tables nécessaires."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Table des cas
    c.execute('''
        CREATE TABLE IF NOT EXISTS cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT,
            status TEXT NOT NULL DEFAULT 'open',
            priority TEXT NOT NULL DEFAULT 'medium',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Table des agents associés aux cas
    c.execute('''
        CREATE TABLE IF NOT EXISTS case_agents (
            case_id INTEGER,
            agent_id TEXT,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (case_id, agent_id),
            FOREIGN KEY (case_id) REFERENCES cases (id) ON DELETE CASCADE
        )
    ''')
    
    # Table des requêtes associées aux cas
    c.execute('''
        CREATE TABLE IF NOT EXISTS case_queries (
            case_id INTEGER,
            query_id INTEGER,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (case_id, query_id),
            FOREIGN KEY (case_id) REFERENCES cases (id) ON DELETE CASCADE,
            FOREIGN KEY (query_id) REFERENCES queries (id) ON DELETE CASCADE
        )
    ''')
    
    # Table des alertes associées aux cas
    c.execute('''
        CREATE TABLE IF NOT EXISTS case_alerts (
            case_id INTEGER,
            alert_id INTEGER,
            added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (case_id, alert_id),
            FOREIGN KEY (case_id) REFERENCES cases (id) ON DELETE CASCADE,
            FOREIGN KEY (alert_id) REFERENCES alerts (id) ON DELETE CASCADE
        )
    ''')
    
    # Table des notes des cas
    c.execute('''
        CREATE TABLE IF NOT EXISTS case_notes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            case_id INTEGER,
            content TEXT NOT NULL,
            author TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (case_id) REFERENCES cases (id) ON DELETE CASCADE
        )
    ''')
    
    # Table des requêtes
    c.execute("""
        CREATE TABLE IF NOT EXISTS queries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query_id TEXT NOT NULL,
            agent_id TEXT NOT NULL,
            query_text TEXT NOT NULL,
            status TEXT NOT NULL,
            submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Table des résultats
    c.execute("""
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            query_id TEXT NOT NULL,
            result_data TEXT NOT NULL,
            received_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Table des alertes
    c.execute('''
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id TEXT NOT NULL,
            rule_title TEXT NOT NULL,
            rule_level TEXT NOT NULL,
            detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            event_data TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'new',
            case_id INTEGER,
            FOREIGN KEY (case_id) REFERENCES cases (id) ON DELETE SET NULL
        )
    ''')
    
    # Index pour les alertes
    c.execute('''
        CREATE INDEX IF NOT EXISTS idx_alerts_rule_id ON alerts (rule_id);
        CREATE INDEX IF NOT EXISTS idx_alerts_detected_at ON alerts (detected_at);
        CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts (status);
        CREATE INDEX IF NOT EXISTS idx_alerts_case_id ON alerts (case_id);
    ''')
    
    # Table des agents
    c.execute("""
        CREATE TABLE IF NOT EXISTS agents (
            agent_id TEXT PRIMARY KEY,
            hostname TEXT NOT NULL,
            ip_address TEXT,
            os_info TEXT,
            last_seen TIMESTAMP NOT NULL
        )
    """)
    
    conn.commit()
    conn.close()
    logging.info("Base de données initialisée avec succès")

def add_query_to_history(query_id: str, agent_id: str, query_text: str, status: str = "pending") -> None:
    """Ajoute une nouvelle requête à l'historique.
    
    Args:
        query_id: Identifiant unique de la requête
        agent_id: Identifiant de l'agent
        query_text: Texte de la requête OQL
        status: Statut de la requête (pending, running, completed, error)
    """
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO queries (query_id, agent_id, query_text, status) VALUES (?, ?, ?, ?)",
                (query_id, agent_id, query_text, status)
            )
            conn.commit()
            logger.debug(f"Requête ajoutée à l'historique: {query_id}")
    except Exception as e:
        logger.error(f"Erreur lors de l'ajout de la requête à l'historique: {e}")
        raise

def store_result_row(query_id: str, result_data: Dict[str, Any]) -> None:
    """Stocke une ligne de résultat dans la base de données.
    
    Args:
        query_id: Identifiant de la requête
        result_data: Données du résultat à stocker
    """
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO results (query_id, result_data) VALUES (?, ?)",
                (query_id, json.dumps(result_data))
            )
            conn.commit()
            logger.debug(f"Résultat stocké pour la requête: {query_id}")
    except Exception as e:
        logger.error(f"Erreur lors du stockage du résultat: {e}")
        raise

def update_query_status(query_id: str, status: str) -> None:
    """Met à jour le statut d'une requête.
    
    Args:
        query_id: Identifiant de la requête
        status: Nouveau statut
    """
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE queries SET status = ? WHERE query_id = ?",
                (status, query_id)
            )
            conn.commit()
            logger.debug(f"Statut de la requête {query_id} mis à jour: {status}")
    except Exception as e:
        logger.error(f"Erreur lors de la mise à jour du statut: {e}")
        raise

def get_all_queries() -> List[Dict[str, Any]]:
    """Récupère toutes les requêtes de l'historique.
    
    Returns:
        List[Dict[str, Any]]: Liste des requêtes avec leurs métadonnées
    """
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT query_id, agent_id, query_text, status, submitted_at
                FROM queries
                ORDER BY submitted_at DESC
            """)
            return [
                {
                    "query_id": row[0],
                    "agent_id": row[1],
                    "query_text": row[2],
                    "status": row[3],
                    "submitted_at": row[4]
                }
                for row in cursor.fetchall()
            ]
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des requêtes: {e}")
        raise

def get_results_for_query(query_id: str) -> List[Dict[str, Any]]:
    """Récupère tous les résultats pour une requête donnée.
    
    Args:
        query_id: Identifiant de la requête
        
    Returns:
        List[Dict[str, Any]]: Liste des résultats
    """
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT result_data FROM results WHERE query_id = ? ORDER BY received_at",
                (query_id,)
            )
            return [json.loads(row[0]) for row in cursor.fetchall()]
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des résultats: {e}")
        raise

def get_agent_timeline(agent_id: str) -> List[Dict[str, Any]]:
    """
    Récupère tous les résultats pour un agent donné, avec les informations de requête.
    Cette fonction est utilisée pour construire la timeline.
    """
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("""
                SELECT r.*, q.query_text, q.agent_id, a.hostname
                FROM results r
                JOIN queries q ON r.query_id = q.query_id
                JOIN agents a ON q.agent_id = a.agent_id
                WHERE q.agent_id = ?
                ORDER BY r.received_at DESC
            """, (agent_id,))
            rows = cursor.fetchall()
            results = []
            for row in rows:
                result = dict(row)
                result['result_data'] = json.loads(result['result_data'])
                results.append(result)
            return results
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de la timeline: {e}")
        raise

def update_agent_info(agent_id: str, hostname: str, ip_address: Optional[str] = None, os_info: Optional[str] = None) -> None:
    """Met à jour ou crée les informations d'un agent."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO agents (agent_id, hostname, ip_address, os_info, last_seen)
                VALUES (?, ?, ?, ?, ?)
            """, (agent_id, hostname, ip_address, os_info, datetime.utcnow().isoformat()))
            conn.commit()
            logger.info(f"Informations de l'agent {agent_id} mises à jour")
    except Exception as e:
        logger.error(f"Erreur lors de la mise à jour des informations de l'agent: {e}")
        raise

def get_all_agents() -> List[Dict[str, Any]]:
    """Récupère la liste de tous les agents connus."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM agents ORDER BY last_seen DESC")
            return [dict(row) for row in cursor.fetchall()]
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des agents: {e}")
        raise

def store_alert(agent_id: str, rule: Dict[str, Any], event_data: Dict[str, Any]) -> None:
    """Stocke une alerte dans la base de données.
    
    Args:
        agent_id: Identifiant de l'agent
        rule: Règle Sigma qui a déclenché l'alerte
        event_data: Données de l'événement qui a déclenché l'alerte
    """
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO alerts (agent_id, rule_id, rule_title, rule_level, event_data)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    agent_id,
                    rule.get('id'),
                    rule.get('title'),
                    rule.get('level', 'low'),
                    json.dumps(event_data)
                )
            )
            conn.commit()
            logger.info(f"Alerte stockée pour la règle {rule.get('title')} sur l'agent {agent_id}")
    except Exception as e:
        logger.error(f"Erreur lors du stockage de l'alerte: {e}")
        raise

def get_all_alerts() -> List[Dict[str, Any]]:
    """Récupère toutes les alertes.
    
    Returns:
        List[Dict[str, Any]]: Liste des alertes avec leurs détails
    """
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, agent_id, rule_id, rule_title, rule_level, event_data, detected_at
                FROM alerts
                ORDER BY detected_at DESC
            """)
            return [
                {
                    "id": row[0],
                    "agent_id": row[1],
                    "rule_id": row[2],
                    "rule_title": row[3],
                    "rule_level": row[4],
                    "event_data": json.loads(row[5]),
                    "detected_at": row[6]
                }
                for row in cursor.fetchall()
            ]
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des alertes: {e}")
        raise

# Fonctions de gestion des cas
def create_case(title: str, description: str, priority: str = "medium") -> int:
    """Crée un nouveau cas d'investigation."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute('''
        INSERT INTO cases (title, description, priority)
        VALUES (?, ?, ?)
    ''', (title, description, priority))
    
    case_id = c.lastrowid
    conn.commit()
    conn.close()
    
    logging.info(f"Cas créé avec l'ID {case_id}")
    return case_id

def get_case(case_id: int) -> Optional[Dict[str, Any]]:
    """Récupère les détails d'un cas spécifique."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute('SELECT * FROM cases WHERE id = ?', (case_id,))
    row = c.fetchone()
    
    if not row:
        conn.close()
        return None
    
    case = {
        'id': row[0],
        'title': row[1],
        'description': row[2],
        'status': row[3],
        'priority': row[4],
        'created_at': row[5],
        'updated_at': row[6]
    }
    
    conn.close()
    return case

def update_case(case_id: int, **kwargs) -> None:
    """Met à jour un cas.
    
    Args:
        case_id: ID du cas
        **kwargs: Champs à mettre à jour (title, description, status, priority)
    """
    try:
        allowed_fields = {"title", "description", "status", "priority"}
        updates = {k: v for k, v in kwargs.items() if k in allowed_fields}
        
        if not updates:
            return
            
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
            cursor.execute(
                f"""
                UPDATE cases
                SET {set_clause}, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
                """,
                (*updates.values(), case_id)
            )
            conn.commit()
            logger.info(f"Cas {case_id} mis à jour")
    except Exception as e:
        logger.error(f"Erreur lors de la mise à jour du cas: {e}")
        raise

def get_all_cases() -> List[Dict[str, Any]]:
    """Récupère tous les cas d'investigation."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute('''
        SELECT c.*,
               COUNT(DISTINCT ca.agent_id) as agent_count,
               COUNT(DISTINCT cq.query_id) as query_count,
               COUNT(DISTINCT cal.alert_id) as alert_count
        FROM cases c
        LEFT JOIN case_agents ca ON c.id = ca.case_id
        LEFT JOIN case_queries cq ON c.id = cq.case_id
        LEFT JOIN case_alerts cal ON c.id = cal.case_id
        GROUP BY c.id
        ORDER BY c.updated_at DESC
    ''')
    
    cases = []
    for row in c.fetchall():
        cases.append({
            'id': row[0],
            'title': row[1],
            'description': row[2],
            'status': row[3],
            'priority': row[4],
            'created_at': row[5],
            'updated_at': row[6],
            'agent_count': row[7],
            'query_count': row[8],
            'alert_count': row[9]
        })
    
    conn.close()
    return cases

def add_agent_to_case(case_id: int, agent_id: str) -> bool:
    """Associe un agent à un cas."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        c.execute('''
            INSERT INTO case_agents (case_id, agent_id)
            VALUES (?, ?)
        ''', (case_id, agent_id))
        
        conn.commit()
        logging.info(f"Agent {agent_id} ajouté au cas {case_id}")
        return True
    except sqlite3.IntegrityError:
        logging.warning(f"L'agent {agent_id} est déjà associé au cas {case_id}")
        return False
    finally:
        conn.close()

def add_query_to_case(case_id: int, query_id: str) -> bool:
    """Associe une requête à un cas."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        c.execute('''
            INSERT INTO case_queries (case_id, query_id)
            VALUES (?, ?)
        ''', (case_id, query_id))
        
        conn.commit()
        logging.info(f"Requête {query_id} ajoutée au cas {case_id}")
        return True
    except sqlite3.IntegrityError:
        logging.warning(f"La requête {query_id} est déjà associée au cas {case_id}")
        return False
    finally:
        conn.close()

def add_alert_to_case(case_id: int, alert_id: int) -> bool:
    """Associe une alerte à un cas."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        c.execute('''
            INSERT INTO case_alerts (case_id, alert_id)
            VALUES (?, ?)
        ''', (case_id, alert_id))
        
        conn.commit()
        logging.info(f"Alerte {alert_id} ajoutée au cas {case_id}")
        return True
    except sqlite3.IntegrityError:
        logging.warning(f"L'alerte {alert_id} est déjà associée au cas {case_id}")
        return False
    finally:
        conn.close()

def add_note(case_id: int, content: str, author: str) -> int:
    """Ajoute une note à un cas."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute('''
        INSERT INTO case_notes (case_id, content, author)
        VALUES (?, ?, ?)
    ''', (case_id, content, author))
    
    note_id = c.lastrowid
    conn.commit()
    conn.close()
    
    logging.info(f"Note ajoutée au cas {case_id}")
    return note_id

def get_case_notes(case_id: int) -> List[Dict[str, Any]]:
    """Récupère les notes d'un cas."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute('''
        SELECT *
        FROM case_notes
        WHERE case_id = ?
        ORDER BY created_at DESC
    ''', (case_id,))
    
    notes = []
    for row in c.fetchall():
        notes.append({
            'id': row[0],
            'case_id': row[1],
            'content': row[2],
            'author': row[3],
            'created_at': row[4]
        })
    
    conn.close()
    return notes

def get_case_agents(case_id: int) -> List[Dict[str, Any]]:
    """Récupère les agents associés à un cas."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute('''
        SELECT a.*
        FROM agents a
        JOIN case_agents ca ON a.id = ca.agent_id
        WHERE ca.case_id = ?
    ''', (case_id,))
    
    agents = []
    for row in c.fetchall():
        agents.append({
            'id': row[0],
            'hostname': row[1],
            'ip_address': row[2],
            'os_info': row[3],
            'last_seen': row[4]
        })
    
    conn.close()
    return agents

def get_case_queries(case_id: int) -> List[Dict[str, Any]]:
    """Récupère les requêtes associées à un cas."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute('''
        SELECT q.*
        FROM queries q
        JOIN case_queries cq ON q.id = cq.query_id
        WHERE cq.case_id = ?
        ORDER BY q.submitted_at DESC
    ''', (case_id,))
    
    queries = []
    for row in c.fetchall():
        queries.append({
            'id': row[0],
            'query_text': row[1],
            'status': row[2],
            'submitted_at': row[3]
        })
    
    conn.close()
    return queries

def get_case_alerts(case_id: int) -> List[Dict[str, Any]]:
    """Récupère les alertes associées à un cas."""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute('''
        SELECT a.*
        FROM alerts a
        JOIN case_alerts cal ON a.id = cal.alert_id
        WHERE cal.case_id = ?
        ORDER BY a.detected_at DESC
    ''', (case_id,))
    
    alerts = []
    for row in c.fetchall():
        alerts.append({
            'id': row[0],
            'rule_id': row[1],
            'rule_title': row[2],
            'rule_level': row[3],
            'detected_at': row[4],
            'details': json.loads(row[5]) if row[5] else None
        })
    
    conn.close()
    return alerts

def add_alert(rule_id: str, rule_title: str, rule_level: str, event_data: Dict[str, Any], case_id: Optional[int] = None) -> int:
    """
    Ajoute une nouvelle alerte à la base de données.
    
    Args:
        rule_id: Identifiant de la règle Sigma
        rule_title: Titre de la règle
        rule_level: Niveau de l'alerte (critical, high, medium, low)
        event_data: Données de l'événement qui a déclenché l'alerte
        case_id: ID du cas associé (optionnel)
        
    Returns:
        int: ID de l'alerte créée
    """
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    try:
        c.execute('''
            INSERT INTO alerts (rule_id, rule_title, rule_level, event_data, case_id)
            VALUES (?, ?, ?, ?, ?)
        ''', (rule_id, rule_title, rule_level, json.dumps(event_data), case_id))
        
        alert_id = c.lastrowid
        conn.commit()
        logging.info(f"Alerte créée avec l'ID {alert_id}")
        return alert_id
    except Exception as e:
        logging.error(f"Erreur lors de la création de l'alerte : {e}")
        raise
    finally:
        conn.close()

def get_alerts(status=None, level=None, case_id=None, limit=100, offset=0):
    """Récupère la liste des alertes avec filtres optionnels."""
    try:
        query = "SELECT * FROM alerts WHERE 1=1"
        params = []
        
        if status:
            query += " AND status = ?"
            params.append(status)
        
        if level:
            query += " AND rule_level = ?"
            params.append(level)
        
        if case_id:
            query += " AND case_id = ?"
            params.append(case_id)
        
        query += " ORDER BY detected_at DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(query, params)
            alerts = [dict(row) for row in cursor.fetchall()]
            
            # Conversion des données JSON
            for alert in alerts:
                alert["event_data"] = json.loads(alert["event_data"])
            
            return alerts
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des alertes: {str(e)}")
        raise

def get_alert(alert_id):
    """Récupère les détails d'une alerte spécifique."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM alerts WHERE id = ?",
                (alert_id,)
            )
            alert = cursor.fetchone()
            
            if alert:
                alert = dict(alert)
                alert["event_data"] = json.loads(alert["event_data"])
                return alert
            return None
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de l'alerte {alert_id}: {str(e)}")
        raise

def update_alert_status(alert_id, status=None, case_id=None):
    """Met à jour le statut d'une alerte."""
    try:
        updates = []
        params = []
        
        if status is not None:
            updates.append("status = ?")
            params.append(status)
        
        if case_id is not None:
            updates.append("case_id = ?")
            params.append(case_id)
        
        if not updates:
            return False
        
        query = f"UPDATE alerts SET {', '.join(updates)} WHERE id = ?"
        params.append(alert_id)
        
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            conn.commit()
            return cursor.rowcount > 0
    except Exception as e:
        logger.error(f"Erreur lors de la mise à jour de l'alerte {alert_id}: {str(e)}")
        raise

def associate_alert_with_case(alert_id, case_id):
    """Associe une alerte à un cas d'investigation."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE alerts SET case_id = ? WHERE id = ?",
                (case_id, alert_id)
            )
            conn.commit()
            return cursor.rowcount > 0
    except Exception as e:
        logger.error(f"Erreur lors de l'association de l'alerte {alert_id} au cas {case_id}: {str(e)}")
        raise 