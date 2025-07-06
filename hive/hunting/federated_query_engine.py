import asyncio
import logging
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import json
import uuid

logger = logging.getLogger(__name__)

class FederatedQueryEngine:
    def __init__(self, node_clients: List, redis_client=None):
        self.nodes = node_clients  # Liste des clients gRPC vers les Nodes
        self.redis = redis_client
        self.query_cache = {}
        self.active_queries = {}

    async def query_all_nodes(self, oql_query: str, timeout: int = 30, target_nodes: List[str] = None) -> Dict[str, Any]:
        """
        Envoie une requête OQL à tous les Nodes en parallèle et fusionne les résultats.
        """
        query_id = str(uuid.uuid4())
        logger.info(f"Executing federated query {query_id}: {oql_query}")
        
        try:
            # Filtrer les nodes si spécifié
            nodes_to_query = self.nodes
            if target_nodes:
                nodes_to_query = [node for node in self.nodes if node.node_id in target_nodes]
            
            if not nodes_to_query:
                return {
                    "success": False,
                    "error": "No target nodes available",
                    "results": [],
                    "query_id": query_id
                }
            
            # Enregistrer la requête comme active
            self.active_queries[query_id] = {
                "query": oql_query,
                "start_time": datetime.now(),
                "nodes": [node.node_id for node in nodes_to_query],
                "status": "running"
            }
            
            # Lancer les requêtes en parallèle sur tous les nodes
            tasks = [self._execute_node_query(node, oql_query, timeout) for node in nodes_to_query]
            all_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Traiter les résultats
            successful_results = []
            failed_nodes = []
            total_execution_time = 0
            
            for i, result in enumerate(all_results):
                node_id = nodes_to_query[i].node_id
                
                if isinstance(result, Exception):
                    failed_nodes.append({
                        "node_id": node_id,
                        "error": str(result)
                    })
                    logger.error(f"Query failed on node {node_id}: {result}")
                else:
                    successful_results.extend(result.get("results", []))
                    total_execution_time += result.get("execution_time_ms", 0)
            
            # Fusionner et dédupliquer les résultats
            merged_results = self._merge_and_deduplicate_results(successful_results)
            
            # Mettre à jour le statut de la requête
            self.active_queries[query_id]["status"] = "completed"
            self.active_queries[query_id]["end_time"] = datetime.now()
            self.active_queries[query_id]["total_results"] = len(merged_results)
            
            # Mettre en cache si nécessaire
            if self.redis and len(merged_results) > 0:
                await self._cache_query_results(query_id, oql_query, merged_results)
            
            return {
                "success": True,
                "query_id": query_id,
                "results": merged_results,
                "total_results": len(merged_results),
                "nodes_contacted": len(nodes_to_query),
                "successful_nodes": len(nodes_to_query) - len(failed_nodes),
                "failed_nodes": failed_nodes,
                "total_execution_time_ms": total_execution_time,
                "execution_timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error executing federated query: {e}")
            if query_id in self.active_queries:
                self.active_queries[query_id]["status"] = "failed"
                self.active_queries[query_id]["error"] = str(e)
            
            return {
                "success": False,
                "error": str(e),
                "query_id": query_id,
                "results": []
            }

    async def _execute_node_query(self, node, oql_query: str, timeout: int) -> Dict[str, Any]:
        """Exécute une requête sur un node spécifique."""
        try:
            start_time = datetime.now()
            
            # Envoyer la requête au node via gRPC
            # result = await node.execute_oql(oql_query, timeout=timeout)
            
            # Simulation de réponse
            await asyncio.sleep(0.1)  # Simuler le délai réseau
            
            execution_time = (datetime.now() - start_time).total_seconds() * 1000
            
            # Simulation de résultats
            mock_results = [
                {
                    "node_id": node.node_id,
                    "agent_id": f"agent_{i}",
                    "result_data": f"Result {i} from {node.node_id}",
                    "timestamp": datetime.now().isoformat(),
                    "metadata": {"source": "mock"}
                }
                for i in range(3)  # 3 résultats par node
            ]
            
            return {
                "node_id": node.node_id,
                "success": True,
                "results": mock_results,
                "execution_time_ms": execution_time
            }
            
        except Exception as e:
            logger.error(f"Error executing query on node {node.node_id}: {e}")
            raise

    def _merge_and_deduplicate_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Fusionne et déduplique les résultats de plusieurs nodes."""
        if not results:
            return []
        
        # Créer un dictionnaire pour la déduplication basée sur un identifiant unique
        unique_results = {}
        
        for result in results:
            # Créer une clé unique basée sur les données importantes
            result_key = self._create_result_key(result)
            
            if result_key not in unique_results:
                unique_results[result_key] = result
            else:
                # Si on a un doublon, garder le plus récent
                existing_timestamp = unique_results[result_key].get("timestamp", "")
                new_timestamp = result.get("timestamp", "")
                
                if new_timestamp > existing_timestamp:
                    unique_results[result_key] = result
        
        # Trier par timestamp
        sorted_results = sorted(
            unique_results.values(),
            key=lambda x: x.get("timestamp", ""),
            reverse=True
        )
        
        return sorted_results

    def _create_result_key(self, result: Dict[str, Any]) -> str:
        """Crée une clé unique pour un résultat."""
        # Combiner les champs importants pour créer une clé unique
        key_parts = [
            result.get("node_id", ""),
            result.get("agent_id", ""),
            result.get("timestamp", ""),
            str(result.get("result_data", ""))
        ]
        return "|".join(key_parts)

    async def _cache_query_results(self, query_id: str, oql_query: str, results: List[Dict[str, Any]]):
        """Met en cache les résultats de la requête."""
        try:
            cache_key = f"federated_query:{query_id}"
            cache_data = {
                "query": oql_query,
                "results": results,
                "cached_at": datetime.now().isoformat(),
                "result_count": len(results)
            }
            
            # Cache pour 1 heure
            await self.redis.setex(cache_key, 3600, json.dumps(cache_data))
            
        except Exception as e:
            logger.error(f"Error caching query results: {e}")

    async def get_cached_results(self, query_id: str) -> Optional[Dict[str, Any]]:
        """Récupère les résultats mis en cache d'une requête."""
        try:
            if not self.redis:
                return None
            
            cache_key = f"federated_query:{query_id}"
            cached_data = await self.redis.get(cache_key)
            
            if cached_data:
                return json.loads(cached_data)
            
            return None
            
        except Exception as e:
            logger.error(f"Error getting cached results: {e}")
            return None

    async def execute_global_hunt(self, hunt_type: str, parameters: Dict[str, Any], target_nodes: List[str] = None) -> Dict[str, Any]:
        """
        Lance une chasse de menace globale sur tous les nodes.
        """
        hunt_id = str(uuid.uuid4())
        logger.info(f"Launching global hunt {hunt_id}: {hunt_type}")
        
        try:
            # Construire la requête OQL basée sur le type de chasse
            oql_query = self._build_hunt_query(hunt_type, parameters)
            
            # Exécuter la requête fédérée
            results = await self.query_all_nodes(oql_query, timeout=60, target_nodes=target_nodes)
            
            # Analyser les résultats pour identifier les menaces
            threats = self._analyze_hunt_results(results.get("results", []), hunt_type)
            
            return {
                "hunt_id": hunt_id,
                "hunt_type": hunt_type,
                "success": results["success"],
                "threats_found": len(threats),
                "threats": threats,
                "query_results": results,
                "launched_at": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error executing global hunt: {e}")
            return {
                "hunt_id": hunt_id,
                "hunt_type": hunt_type,
                "success": False,
                "error": str(e),
                "threats_found": 0,
                "threats": []
            }

    def _build_hunt_query(self, hunt_type: str, parameters: Dict[str, Any]) -> str:
        """Construit une requête OQL basée sur le type de chasse."""
        if hunt_type == "malware":
            return "FROM all_agents:process_launch WHERE process_name IN ('cmd.exe', 'powershell.exe', 'wscript.exe')"
        elif hunt_type == "lateral_movement":
            return "FROM all_agents:network_connections WHERE state = 'ESTABLISHED' AND process_name = 'svchost.exe'"
        elif hunt_type == "data_exfiltration":
            return "FROM all_agents:file_access WHERE file_path LIKE '%.exe' OR file_path LIKE '%.dll'"
        elif hunt_type == "persistence":
            return "FROM all_agents:registry_access WHERE key_path LIKE '%Run%' OR key_path LIKE '%Startup%'"
        else:
            # Requête générique
            return "FROM all_agents:* WHERE severity = 'high'"

    def _analyze_hunt_results(self, results: List[Dict[str, Any]], hunt_type: str) -> List[Dict[str, Any]]:
        """Analyse les résultats de chasse pour identifier les menaces."""
        threats = []
        
        for result in results:
            # Logique d'analyse basée sur le type de chasse
            if hunt_type == "malware":
                if self._is_suspicious_process(result):
                    threats.append({
                        "type": "malware",
                        "severity": "high",
                        "description": f"Suspicious process detected: {result.get('result_data', '')}",
                        "node_id": result.get("node_id"),
                        "agent_id": result.get("agent_id"),
                        "timestamp": result.get("timestamp")
                    })
            
            elif hunt_type == "lateral_movement":
                if self._is_lateral_movement(result):
                    threats.append({
                        "type": "lateral_movement",
                        "severity": "medium",
                        "description": f"Potential lateral movement detected",
                        "node_id": result.get("node_id"),
                        "agent_id": result.get("agent_id"),
                        "timestamp": result.get("timestamp")
                    })
        
        return threats

    def _is_suspicious_process(self, result: Dict[str, Any]) -> bool:
        """Détermine si un processus est suspect."""
        # Logique simplifiée pour la démonstration
        suspicious_indicators = ["cmd", "powershell", "wscript", "suspicious"]
        result_data = str(result.get("result_data", "")).lower()
        
        return any(indicator in result_data for indicator in suspicious_indicators)

    def _is_lateral_movement(self, result: Dict[str, Any]) -> bool:
        """Détermine s'il y a un mouvement latéral."""
        # Logique simplifiée pour la démonstration
        return "network" in str(result.get("result_data", "")).lower()

    def get_query_status(self, query_id: str) -> Optional[Dict[str, Any]]:
        """Récupère le statut d'une requête active."""
        return self.active_queries.get(query_id)

    def get_active_queries(self) -> List[Dict[str, Any]]:
        """Récupère la liste des requêtes actives."""
        return [
            {
                "query_id": qid,
                **query_info
            }
            for qid, query_info in self.active_queries.items()
        ]

    def cleanup_old_queries(self, max_age_hours: int = 24):
        """Nettoie les anciennes requêtes du cache."""
        cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
        
        queries_to_remove = []
        for query_id, query_info in self.active_queries.items():
            if query_info.get("start_time", datetime.now()) < cutoff_time:
                queries_to_remove.append(query_id)
        
        for query_id in queries_to_remove:
            del self.active_queries[query_id]
        
        logger.info(f"Cleaned up {len(queries_to_remove)} old queries") 