import os
import yaml
import logging
import json
from typing import List, Dict, Any, Optional
from pathlib import Path
from datetime import datetime
from sigma.collection import SigmaCollection
from sigma.backends.sqlite import SQLiteBackend
from sigma.rule import SigmaRule
from ..notifications.dispatcher import NotificationDispatcher

logger = logging.getLogger(__name__)

class SigmaDetector:
    """
    Charge les règles Sigma et vérifie les événements par rapport à elles.
    """
    def __init__(self, rules_path: Optional[str] = None, notification_dispatcher: NotificationDispatcher = None):
        self.rules: Optional[SigmaCollection] = None
        self.rules_metadata: Dict[str, Dict[str, Any]] = {}
        self.backend = SQLiteBackend()
        self.dispatcher = notification_dispatcher
        
        if rules_path:
            self.load_rules(rules_path)
        else:
            logging.warning("Aucun chemin de règles Sigma n'a été configuré. Le détecteur est désactivé.")

    def load_rules(self, rules_path: str) -> bool:
        """
        Charge les règles Sigma depuis le chemin spécifié.
        
        Args:
            rules_path: Chemin vers le répertoire ou fichier de règles
            
        Returns:
            bool: True si le chargement a réussi, False sinon
        """
        try:
            self.rules = SigmaCollection.load_ruleset(paths=[rules_path])
            self._index_rules_metadata()
            logging.info(f"{len(self.rules)} règles Sigma ont été chargées depuis {rules_path}")
            return True
        except Exception as e:
            logging.error(f"Erreur lors du chargement des règles Sigma : {e}", exc_info=True)
            self.rules = None
            return False

    def _index_rules_metadata(self) -> None:
        """
        Indexe les métadonnées des règles pour un accès rapide.
        """
        if not self.rules:
            return
            
        for rule in self.rules:
            self.rules_metadata[rule.id] = {
                'title': rule.title,
                'description': rule.description,
                'level': rule.level,
                'tags': rule.tags,
                'author': rule.author,
                'date': rule.date,
                'modified': rule.modified,
                'status': rule.status,
                'falsepositives': rule.falsepositives,
                'references': rule.references
            }

    def get_rule_metadata(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """
        Récupère les métadonnées d'une règle spécifique.
        
        Args:
            rule_id: Identifiant de la règle
            
        Returns:
            Optional[Dict[str, Any]]: Métadonnées de la règle ou None si non trouvée
        """
        return self.rules_metadata.get(rule_id)

    def check(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Vérifie un événement par rapport à toutes les règles chargées.
        
        Args:
            event: Événement à vérifier
            
        Returns:
            List[Dict[str, Any]]: Liste des règles correspondantes avec leurs détails
        """
        if not self.rules:
            return []
        
        matching_rules = []
        try:
            for rule in self.rules:
                if rule.check([event]):
                    matching_rules.append({
                        'id': rule.id,
                        'title': rule.title,
                        'level': rule.level,
                        'description': rule.description,
                        'tags': rule.tags,
                        'detected_at': datetime.now().isoformat(),
                        'event': event
                    })
                    if rule.level in ["high", "critical"]:
                        alert = {
                            "title": "Sigma Rule Match: " + rule.title,
                            "severity": rule.level,
                            "agent_name": event.get('agent_name', 'Unknown'),
                            "details": event
                        }
                        self.dispatcher.dispatch(alert)
        except Exception as e:
            logging.debug(f"Erreur lors de la vérification de l'événement avec Sigma : {e}")

        return matching_rules

    def get_all_rules(self) -> List[Dict[str, Any]]:
        """
        Récupère la liste de toutes les règles chargées avec leurs métadonnées.
        
        Returns:
            List[Dict[str, Any]]: Liste des règles avec leurs métadonnées
        """
        if not self.rules:
            return []
            
        return [
            {
                'id': rule.id,
                **self.rules_metadata[rule.id]
            }
            for rule in self.rules
        ]

    def get_rules_by_level(self, level: str) -> List[Dict[str, Any]]:
        """
        Récupère les règles d'un niveau spécifique.
        
        Args:
            level: Niveau des règles à récupérer (critical, high, medium, low)
            
        Returns:
            List[Dict[str, Any]]: Liste des règles du niveau spécifié
        """
        if not self.rules:
            return []
            
        return [
            {
                'id': rule.id,
                **self.rules_metadata[rule.id]
            }
            for rule in self.rules
            if rule.level == level
        ]

    def get_rules_by_tag(self, tag: str) -> List[Dict[str, Any]]:
        """
        Récupère les règles ayant un tag spécifique.
        
        Args:
            tag: Tag à rechercher
            
        Returns:
            List[Dict[str, Any]]: Liste des règles avec le tag spécifié
        """
        if not self.rules:
            return []
            
        return [
            {
                'id': rule.id,
                **self.rules_metadata[rule.id]
            }
            for rule in self.rules
            if tag in rule.tags
        ]

    def export_rules_to_sqlite(self, db_path: str) -> bool:
        """
        Exporte les règles vers une base de données SQLite.
        
        Args:
            db_path: Chemin vers la base de données SQLite
            
        Returns:
            bool: True si l'export a réussi, False sinon
        """
        if not self.rules:
            return False
            
        try:
            self.backend.convert(self.rules, db_path)
            logging.info(f"Règles exportées vers {db_path}")
            return True
        except Exception as e:
            logging.error(f"Erreur lors de l'export des règles vers SQLite : {e}")
            return False

    def _load_rules(self) -> None:
        """Charge toutes les règles Sigma depuis le répertoire configuré."""
        if not self.rules_path.exists():
            logger.warning(f"Le répertoire des règles Sigma n'existe pas: {self.rules_path}")
            return
            
        for rule_file in self.rules_path.glob("*.yml"):
            try:
                with open(rule_file, 'r', encoding='utf-8') as f:
                    rule = yaml.safe_load(f)
                    if self._validate_rule(rule):
                        self.rules.append(rule)
                        logger.info(f"Règle Sigma chargée: {rule.get('title')} ({rule.get('id')})")
            except Exception as e:
                logger.error(f"Erreur lors du chargement de la règle {rule_file}: {e}")
                
    def _validate_rule(self, rule: Dict[str, Any]) -> bool:
        """Valide qu'une règle contient tous les champs requis.
        
        Args:
            rule: La règle à valider
            
        Returns:
            bool: True si la règle est valide, False sinon
        """
        required_fields = ['title', 'id', 'detection', 'logsource']
        return all(field in rule for field in required_fields)
        
    def check_event(self, event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Vérifie si un événement correspond à une ou plusieurs règles Sigma.
        
        Args:
            event: L'événement à analyser
            
        Returns:
            List[Dict[str, Any]]: Liste des règles correspondantes
        """
        matches = []
        
        for rule in self.rules:
            if self._evaluate_rule(rule, event):
                matches.append(rule)
                
        return matches
        
    def _evaluate_rule(self, rule: Dict[str, Any], event: Dict[str, Any]) -> bool:
        """Évalue si un événement correspond à une règle Sigma.
        
        Args:
            rule: La règle à évaluer
            event: L'événement à analyser
            
        Returns:
            bool: True si l'événement correspond à la règle
        """
        try:
            # Vérifier la source de log
            logsource = rule.get('logsource', {})
            if logsource.get('product') != 'osiris':
                return False
                
            # Vérifier la catégorie si spécifiée
            if 'category' in logsource and event.get('event_type') != logsource['category']:
                return False
                
            # Évaluer la condition de détection
            detection = rule.get('detection', {})
            selection = detection.get('selection', {})
            keywords = detection.get('keywords', [])
            
            # Vérifier les critères de sélection
            selection_match = all(
                event.get(key) == value
                for key, value in selection.items()
            )
            
            # Vérifier les mots-clés
            keywords_match = False
            if keywords:
                event_str = str(event).lower()
                keywords_match = any(keyword.lower() in event_str for keyword in keywords)
                
            # Évaluer la condition finale
            condition = detection.get('condition', 'selection')
            if condition == 'selection':
                return selection_match
            elif condition == 'selection and keywords':
                return selection_match and keywords_match
            elif condition == 'selection or keywords':
                return selection_match or keywords_match
                
            return False
            
        except Exception as e:
            logger.error(f"Erreur lors de l'évaluation de la règle {rule.get('id')}: {e}")
            return False

    def _normalize_event_for_sigma(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Normalise un événement de la timeline pour le format Sigma.
        
        Args:
            event: Événement de la timeline
            
        Returns:
            Événement au format Sigma
        """
        sigma_event = {
            'timestamp': event['timestamp'],
            'source': event['source'],
            'event_type': event['event_type']
        }
        
        # Ajouter les détails spécifiques selon la source
        if event['source'] == 'processes':
            sigma_event.update({
                'process': {
                    'name': event['details'].get('name'),
                    'pid': event['details'].get('pid'),
                    'ppid': event['details'].get('ppid'),
                    'command_line': event['details'].get('command_line'),
                    'user': event['details'].get('user')
                }
            })
        elif event['source'] == 'fs':
            sigma_event.update({
                'file': {
                    'path': event['details'].get('path'),
                    'size': event['details'].get('size'),
                    'md5': event['details'].get('md5'),
                    'sha256': event['details'].get('sha256')
                }
            })
        elif event['source'] == 'network':
            sigma_event.update({
                'network': {
                    'local_address': event['details'].get('local_address'),
                    'local_port': event['details'].get('local_port'),
                    'remote_address': event['details'].get('remote_address'),
                    'remote_port': event['details'].get('remote_port'),
                    'protocol': event['details'].get('protocol'),
                    'state': event['details'].get('state')
                }
            })
        elif event['source'] in ['prefetch', 'amcache']:
            sigma_event.update({
                'program': {
                    'name': event['details'].get('executable_filename') or event['details'].get('program_path'),
                    'path': event['details'].get('source_path') or event['details'].get('program_path'),
                    'sha1': event['details'].get('sha1')
                }
            })
        elif event['source'] == 'yara':
            sigma_event.update({
                'yara': {
                    'rule_name': event['details'].get('rule_name'),
                    'file_path': event['details'].get('file_path'),
                    'tags': event['details'].get('tags', []),
                    'matched_strings': event['details'].get('matched_strings', [])
                }
            })
        
        return sigma_event

    def get_rule_details(self, rule: SigmaRule) -> Dict[str, Any]:
        """
        Extrait les détails importants d'une règle Sigma.
        
        Args:
            rule: Règle Sigma
            
        Returns:
            Dictionnaire contenant les détails de la règle
        """
        return {
            'id': rule.id,
            'title': rule.title,
            'description': rule.description,
            'author': rule.author,
            'date': rule.date,
            'modified': rule.modified,
            'status': rule.status,
            'level': rule.level,
            'tags': rule.tags,
            'falsepositives': rule.falsepositives,
            'references': rule.references
        } 