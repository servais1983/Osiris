import logging
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
import json
import redis

logger = logging.getLogger(__name__)

class RiskScorer:
    def __init__(self, redis_client: redis.Redis):
        # On utilise Redis pour stocker les scores de risque en temps réel
        self.redis = redis_client
        self.decay_factor = 0.95  # Facteur de décroissance par heure
        self.critical_threshold = 100
        self.high_threshold = 70
        self.medium_threshold = 40
        self.low_threshold = 20

    def update_risk_score(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Met à jour le score de risque d'un utilisateur en fonction d'un nouvel événement.
        """
        try:
            if 'anomaly_score' not in event or event['anomaly_score'] <= 0:
                return event
            
            user = event.get('user')
            if not user:
                return event
            
            # Calculer le nouveau score de risque
            new_score = self._calculate_risk_score(user, event['anomaly_score'])
            
            # Mettre à jour l'événement avec les informations de risque
            event['user_risk_score'] = new_score
            event['risk_level'] = self._determine_risk_level(new_score)
            
            # Vérifier si le seuil critique est dépassé
            if new_score > self.critical_threshold:
                event['critical_risk'] = True
                event['tags'] = event.get('tags', []) + ['critical_risk']
                logger.warning(f"CRITICAL RISK: User {user} has crossed the risk threshold! Score: {new_score}")
                
                # Déclencher une alerte critique
                self._trigger_critical_alert(user, new_score, event)
            
            elif new_score > self.high_threshold:
                event['high_risk'] = True
                event['tags'] = event.get('tags', []) + ['high_risk']
                logger.info(f"HIGH RISK: User {user} risk score: {new_score}")
            
            return event
            
        except Exception as e:
            logger.error(f"Error updating risk score: {e}")
            return event

    def _calculate_risk_score(self, user: str, anomaly_score: int) -> int:
        """
        Calcule le nouveau score de risque en tenant compte de la décroissance temporelle.
        """
        key = f"risk_score:user:{user}"
        
        try:
            # Récupérer le score actuel
            current_score = self.redis.get(key)
            if current_score:
                current_score = int(current_score)
            else:
                current_score = 0
            
            # Appliquer la décroissance temporelle
            decayed_score = self._apply_time_decay(current_score)
            
            # Ajouter le nouveau score d'anomalie
            new_score = decayed_score + anomaly_score
            
            # Limiter le score maximum
            new_score = min(new_score, 1000)
            
            # Sauvegarder le nouveau score
            self.redis.set(key, new_score, ex=24*3600)  # Expire après 24h
            
            logger.debug(f"User {user} risk score: {current_score} -> {new_score} (anomaly: {anomaly_score})")
            
            return new_score
            
        except Exception as e:
            logger.error(f"Error calculating risk score for user {user}: {e}")
            return 0

    def _apply_time_decay(self, current_score: int) -> int:
        """
        Applique la décroissance temporelle au score de risque.
        """
        # En production, on pourrait utiliser un timestamp pour calculer la décroissance exacte
        # Pour l'instant, on applique une décroissance simple
        return int(current_score * self.decay_factor)

    def _determine_risk_level(self, score: int) -> str:
        """Détermine le niveau de risque basé sur le score."""
        if score >= self.critical_threshold:
            return 'critical'
        elif score >= self.high_threshold:
            return 'high'
        elif score >= self.medium_threshold:
            return 'medium'
        elif score >= self.low_threshold:
            return 'low'
        else:
            return 'normal'

    def _trigger_critical_alert(self, user: str, score: int, event: Dict[str, Any]):
        """
        Déclenche une alerte critique quand le seuil est dépassé.
        """
        try:
            alert_data = {
                'type': 'critical_risk_alert',
                'user': user,
                'risk_score': score,
                'timestamp': datetime.now().isoformat(),
                'event_details': {
                    'type': event.get('type'),
                    'anomaly_score': event.get('anomaly_score'),
                    'anomaly_reasons': event.get('anomaly_reasons', []),
                    'host': event.get('host'),
                    'agent_id': event.get('agent_id')
                },
                'recommended_actions': [
                    'Isolate user account',
                    'Review recent activities',
                    'Check for lateral movement',
                    'Initiate incident response'
                ]
            }
            
            # Stocker l'alerte critique
            alert_key = f"critical_alert:{user}:{int(datetime.now().timestamp())}"
            self.redis.set(alert_key, json.dumps(alert_data), ex=7*24*3600)  # 7 jours
            
            # Ajouter à la liste des alertes critiques
            self.redis.lpush('critical_alerts', alert_key)
            self.redis.ltrim('critical_alerts', 0, 99)  # Garder seulement les 100 dernières
            
            logger.warning(f"Critical risk alert triggered for user {user}")
            
        except Exception as e:
            logger.error(f"Error triggering critical alert: {e}")

    def get_user_risk_score(self, user: str) -> Optional[int]:
        """Récupère le score de risque actuel d'un utilisateur."""
        try:
            key = f"risk_score:user:{user}"
            score = self.redis.get(key)
            return int(score) if score else 0
            
        except Exception as e:
            logger.error(f"Error getting risk score for user {user}: {e}")
            return None

    def get_high_risk_users(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Récupère la liste des utilisateurs à haut risque."""
        try:
            high_risk_users = []
            
            # Scanner toutes les clés de score de risque
            pattern = "risk_score:user:*"
            
            for key in self.redis.scan_iter(match=pattern):
                user = key.decode('utf-8').split(':', 2)[2]  # Extraire le nom d'utilisateur
                score = self.redis.get(key)
                
                if score:
                    score = int(score)
                    if score >= self.high_threshold:
                        high_risk_users.append({
                            'user': user,
                            'risk_score': score,
                            'risk_level': self._determine_risk_level(score),
                            'last_updated': self._get_last_activity(user)
                        })
            
            # Trier par score décroissant et limiter
            high_risk_users.sort(key=lambda x: x['risk_score'], reverse=True)
            return high_risk_users[:limit]
            
        except Exception as e:
            logger.error(f"Error getting high risk users: {e}")
            return []

    def _get_last_activity(self, user: str) -> Optional[str]:
        """Récupère la dernière activité d'un utilisateur."""
        try:
            # En production, on pourrait stocker le timestamp de la dernière activité
            # Pour l'instant, on retourne None
            return None
            
        except Exception as e:
            logger.error(f"Error getting last activity for user {user}: {e}")
            return None

    def reset_user_risk_score(self, user: str) -> bool:
        """Remet à zéro le score de risque d'un utilisateur."""
        try:
            key = f"risk_score:user:{user}"
            self.redis.delete(key)
            logger.info(f"Reset risk score for user {user}")
            return True
            
        except Exception as e:
            logger.error(f"Error resetting risk score for user {user}: {e}")
            return False

    def get_risk_statistics(self) -> Dict[str, Any]:
        """Récupère les statistiques de risque."""
        try:
            stats = {
                'total_users_monitored': 0,
                'critical_risk_users': 0,
                'high_risk_users': 0,
                'medium_risk_users': 0,
                'low_risk_users': 0,
                'normal_risk_users': 0,
                'average_risk_score': 0,
                'critical_alerts_count': 0
            }
            
            # Compter les utilisateurs par niveau de risque
            pattern = "risk_score:user:*"
            total_score = 0
            user_count = 0
            
            for key in self.redis.scan_iter(match=pattern):
                score = self.redis.get(key)
                if score:
                    score = int(score)
                    total_score += score
                    user_count += 1
                    
                    risk_level = self._determine_risk_level(score)
                    stats[f'{risk_level}_risk_users'] += 1
            
            stats['total_users_monitored'] = user_count
            stats['average_risk_score'] = total_score / user_count if user_count > 0 else 0
            
            # Compter les alertes critiques
            stats['critical_alerts_count'] = self.redis.llen('critical_alerts')
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting risk statistics: {e}")
            return {}

    def get_critical_alerts(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Récupère les alertes critiques récentes."""
        try:
            alerts = []
            alert_keys = self.redis.lrange('critical_alerts', 0, limit - 1)
            
            for key in alert_keys:
                alert_data = self.redis.get(key)
                if alert_data:
                    alerts.append(json.loads(alert_data))
            
            return alerts
            
        except Exception as e:
            logger.error(f"Error getting critical alerts: {e}")
            return []

    def update_thresholds(self, new_thresholds: Dict[str, int]):
        """Met à jour les seuils de risque."""
        if 'critical' in new_thresholds:
            self.critical_threshold = new_thresholds['critical']
        if 'high' in new_thresholds:
            self.high_threshold = new_thresholds['high']
        if 'medium' in new_thresholds:
            self.medium_threshold = new_thresholds['medium']
        if 'low' in new_thresholds:
            self.low_threshold = new_thresholds['low']
        
        logger.info(f"Updated risk thresholds: {new_thresholds}")

    def get_current_thresholds(self) -> Dict[str, int]:
        """Récupère les seuils actuels."""
        return {
            'critical': self.critical_threshold,
            'high': self.high_threshold,
            'medium': self.medium_threshold,
            'low': self.low_threshold
        }

    def set_decay_factor(self, factor: float):
        """Définit le facteur de décroissance."""
        if 0 < factor < 1:
            self.decay_factor = factor
            logger.info(f"Updated decay factor: {factor}")
        else:
            logger.error(f"Invalid decay factor: {factor}. Must be between 0 and 1.")

    def get_decay_factor(self) -> float:
        """Récupère le facteur de décroissance actuel."""
        return self.decay_factor 