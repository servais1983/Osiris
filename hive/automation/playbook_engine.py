import yaml
import json
import time
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
import asyncio

logger = logging.getLogger(__name__)

class PlaybookEngine:
    def __init__(self, playbooks_path: str = "hive/playbooks/", db_client=None, redis_client=None):
        self.playbooks_path = Path(playbooks_path)
        self.playbooks = {}
        self.db_client = db_client
        self.redis_client = redis_client
        self._load_playbooks()
    
    def _load_playbooks(self):
        """Charge tous les fichiers .yml du répertoire des playbooks."""
        if not self.playbooks_path.exists():
            logger.warning(f"Playbooks directory {self.playbooks_path} does not exist")
            return
            
        for yaml_file in self.playbooks_path.glob("*.yml"):
            try:
                with open(yaml_file, 'r', encoding='utf-8') as f:
                    playbook = yaml.safe_load(f)
                    
                # Indexer par le titre de la règle de déclenchement
                trigger_title = playbook.get('trigger', {}).get('sigma_rule_title')
                if trigger_title:
                    self.playbooks[trigger_title] = playbook
                    logger.info(f"Loaded playbook: {playbook['name']} -> {trigger_title}")
                else:
                    logger.warning(f"Playbook {yaml_file} has no valid trigger")
                    
            except Exception as e:
                logger.error(f"Error loading playbook {yaml_file}: {e}")

    def on_alert(self, alert: Dict[str, Any], dry_run: bool = False) -> Dict[str, Any]:
        """
        Méthode principale appelée par le SigmaDetector à chaque nouvelle alerte.
        """
        playbook = self.playbooks.get(alert.get('title', ''))
        if not playbook:
            logger.debug(f"No playbook found for alert: {alert.get('title')}")
            return {"executed": False, "reason": "No matching playbook"}
        
        logger.info(f"Playbook '{playbook['name']}' triggered by alert '{alert.get('title')}'!")
        
        # Vérifier les conditions
        if not self._check_conditions(playbook, alert):
            logger.info(f"Playbook conditions not met for alert: {alert.get('title')}")
            return {"executed": False, "reason": "Conditions not met"}
        
        # Exécuter la séquence
        results = []
        start_time = time.time()
        
        for step in playbook.get('sequence', []):
            step_result = self._execute_step(step, alert, dry_run)
            results.append(step_result)
            
            # Si une étape échoue et qu'on ne doit pas continuer
            if not step_result['success'] and not playbook.get('settings', {}).get('continue_on_failure', False):
                break
        
        execution_time = (time.time() - start_time) * 1000
        
        # Logger l'exécution
        self._log_execution(playbook, alert, results, execution_time, dry_run)
        
        return {
            "executed": True,
            "playbook_name": playbook['name'],
            "steps_executed": len(results),
            "execution_time_ms": execution_time,
            "results": results,
            "dry_run": dry_run
        }

    def _check_conditions(self, playbook: Dict, alert: Dict) -> bool:
        """Vérifie si les conditions du playbook sont remplies."""
        conditions = playbook.get('conditions', [])
        if not conditions:
            return True  # Pas de conditions = toujours exécuter
            
        for condition in conditions:
            field = condition.get('field')
            operator = condition.get('operator')
            value = condition.get('value')
            
            if not all([field, operator, value]):
                continue
                
            # Extraire la valeur du champ dans l'alerte
            alert_value = self._extract_field_value(alert, field)
            
            if not self._evaluate_condition(alert_value, operator, value):
                return False
                
        return True

    def _extract_field_value(self, data: Dict, field_path: str) -> Any:
        """Extrait une valeur d'un chemin de champ (ex: 'alert.severity')."""
        keys = field_path.split('.')
        current = data
        
        for key in keys:
            if isinstance(current, dict) and key in current:
                current = current[key]
            else:
                return None
                
        return current

    def _evaluate_condition(self, actual_value: Any, operator: str, expected_value: Any) -> bool:
        """Évalue une condition avec l'opérateur spécifié."""
        if actual_value is None:
            return False
            
        if operator == "eq":
            return actual_value == expected_value
        elif operator == "ne":
            return actual_value != expected_value
        elif operator == "gt":
            return actual_value > expected_value
        elif operator == "gte":
            return actual_value >= expected_value
        elif operator == "lt":
            return actual_value < expected_value
        elif operator == "lte":
            return actual_value <= expected_value
        elif operator == "in":
            return actual_value in expected_value
        elif operator == "contains":
            return expected_value in actual_value
        else:
            logger.warning(f"Unknown operator: {operator}")
            return False

    def _execute_step(self, step: Dict, alert: Dict, dry_run: bool) -> Dict[str, Any]:
        """Exécute une étape du playbook."""
        step_name = step.get('name', 'Unknown')
        action = step.get('action', '')
        parameters = step.get('parameters', {})
        timeout = step.get('timeout', 30)
        
        logger.info(f"Executing step: {step_name} (action: {action})")
        
        # Remplacer les variables du template
        resolved_params = self._resolve_template_variables(parameters, alert)
        
        if dry_run:
            logger.info(f"[DRY RUN] Would execute action '{action}' with params '{resolved_params}'")
            return {
                "step_name": step_name,
                "action": action,
                "success": True,
                "message": "Dry run successful",
                "execution_time_ms": 0
            }
        
        # Exécuter l'action
        start_time = time.time()
        try:
            success, message = self._execute_action(action, resolved_params, timeout)
            execution_time = (time.time() - start_time) * 1000
            
            return {
                "step_name": step_name,
                "action": action,
                "success": success,
                "message": message,
                "execution_time_ms": execution_time
            }
            
        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            logger.error(f"Error executing step {step_name}: {e}")
            return {
                "step_name": step_name,
                "action": action,
                "success": False,
                "message": str(e),
                "execution_time_ms": execution_time
            }

    def _resolve_template_variables(self, parameters: Dict, alert: Dict) -> Dict:
        """Remplace les variables de template par leurs valeurs réelles."""
        resolved = {}
        
        for key, value in parameters.items():
            if isinstance(value, str) and '{{' in value and '}}' in value:
                # Variable de template
                resolved_value = self._resolve_template_string(value, alert)
                resolved[key] = resolved_value
            elif isinstance(value, dict):
                # Récursion pour les dictionnaires imbriqués
                resolved[key] = self._resolve_template_variables(value, alert)
            elif isinstance(value, list):
                # Récursion pour les listes
                resolved[key] = [
                    self._resolve_template_variables(item, alert) if isinstance(item, dict)
                    else self._resolve_template_string(item, alert) if isinstance(item, str)
                    else item
                    for item in value
                ]
            else:
                resolved[key] = value
                
        return resolved

    def _resolve_template_string(self, template: str, alert: Dict) -> str:
        """Remplace les variables dans une chaîne de template."""
        try:
            # Simple remplacement de variables
            result = template
            
            # Remplacer {{ alert.field }} par la valeur
            if '{{ alert.' in result:
                for key, value in alert.items():
                    placeholder = f"{{{{ alert.{key} }}}}"
                    if placeholder in result:
                        result = result.replace(placeholder, str(value))
                        
            # Remplacer {{ alert.data.field }} par la valeur
            if '{{ alert.data.' in result and 'data' in alert:
                for key, value in alert['data'].items():
                    placeholder = f"{{{{ alert.data.{key} }}}}"
                    if placeholder in result:
                        result = result.replace(placeholder, str(value))
                        
            return result
            
        except Exception as e:
            logger.error(f"Error resolving template {template}: {e}")
            return template

    def _execute_action(self, action: str, parameters: Dict, timeout: int) -> tuple[bool, str]:
        """Exécute une action spécifique."""
        try:
            if action == "kill_process":
                return self._execute_kill_process(parameters)
            elif action == "isolate":
                return self._execute_isolate(parameters)
            elif action == "create_case":
                return self._execute_create_case(parameters)
            elif action == "send_notification":
                return self._execute_send_notification(parameters)
            elif action == "collect_evidence":
                return self._execute_collect_evidence(parameters)
            else:
                return False, f"Unknown action: {action}"
                
        except Exception as e:
            return False, f"Error executing action {action}: {str(e)}"

    def _execute_kill_process(self, parameters: Dict) -> tuple[bool, str]:
        """Exécute l'action kill_process."""
        # Cette action devrait être exécutée sur l'agent via gRPC
        # Pour l'instant, on simule
        pid = parameters.get('pid')
        if not pid:
            return False, "No PID provided"
            
        logger.info(f"Would kill process {pid} on agent")
        return True, f"Process {pid} termination requested"

    def _execute_isolate(self, parameters: Dict) -> tuple[bool, str]:
        """Exécute l'action isolate."""
        # Cette action devrait être exécutée sur l'agent via gRPC
        logger.info("Would isolate host")
        return True, "Host isolation requested"

    def _execute_create_case(self, parameters: Dict) -> tuple[bool, str]:
        """Exécute l'action create_case."""
        # Cette action est interne au Hive
        title = parameters.get('title', 'Automated Case')
        priority = parameters.get('priority', 'Medium')
        
        logger.info(f"Would create case: {title} with priority {priority}")
        return True, f"Case '{title}' creation requested"

    def _execute_send_notification(self, parameters: Dict) -> tuple[bool, str]:
        """Exécute l'action send_notification."""
        channel = parameters.get('channel', 'slack')
        message = parameters.get('message', 'Automated notification')
        
        logger.info(f"Would send notification to {channel}: {message}")
        return True, f"Notification to {channel} requested"

    def _execute_collect_evidence(self, parameters: Dict) -> tuple[bool, str]:
        """Exécute l'action collect_evidence."""
        evidence_type = parameters.get('type', 'unknown')
        target = parameters.get('target', 'unknown')
        
        logger.info(f"Would collect {evidence_type} evidence from {target}")
        return True, f"Evidence collection of type {evidence_type} requested"

    def _log_execution(self, playbook: Dict, alert: Dict, results: List, execution_time: float, dry_run: bool):
        """Enregistre l'exécution du playbook dans les logs."""
        try:
            if self.db_client:
                # Log dans la base de données
                log_entry = {
                    "playbook_name": playbook['name'],
                    "alert_title": alert.get('title'),
                    "agent_id": alert.get('agent_id'),
                    "execution_time_ms": execution_time,
                    "steps_executed": len(results),
                    "successful_steps": sum(1 for r in results if r['success']),
                    "dry_run": dry_run,
                    "executed_at": time.time()
                }
                
                # self.db_client.insert_playbook_execution(log_entry)
                logger.info(f"Playbook execution logged: {playbook['name']}")
                
        except Exception as e:
            logger.error(f"Error logging playbook execution: {e}")

    def get_playbook_status(self, playbook_name: str) -> Dict[str, Any]:
        """Récupère le statut d'un playbook."""
        for playbook in self.playbooks.values():
            if playbook['name'] == playbook_name:
                return {
                    "name": playbook['name'],
                    "enabled": playbook.get('settings', {}).get('enabled', True),
                    "trigger": playbook.get('trigger', {}),
                    "steps_count": len(playbook.get('sequence', [])),
                    "conditions_count": len(playbook.get('conditions', []))
                }
        return {}

    def list_playbooks(self) -> List[Dict[str, Any]]:
        """Liste tous les playbooks disponibles."""
        return [
            {
                "name": playbook['name'],
                "description": playbook.get('description', ''),
                "trigger": playbook.get('trigger', {}),
                "enabled": playbook.get('settings', {}).get('enabled', True)
            }
            for playbook in self.playbooks.values()
        ] 