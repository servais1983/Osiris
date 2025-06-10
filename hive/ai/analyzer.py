import os
import json
import logging
import httpx
from typing import Dict, Any, Optional
from dotenv import load_dotenv

# Chargement des variables d'environnement
load_dotenv()

# Configuration du logging
logger = logging.getLogger(__name__)

class AlertAnalyzer:
    """Analyseur d'alertes basé sur l'IA (Gemini)."""
    
    def __init__(self):
        """Initialise l'analyseur avec la clé API Gemini."""
        self.api_key = os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError("La clé API Gemini n'est pas configurée")
        
        self.api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={self.api_key}"
    
    async def analyze_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyse une alerte avec l'IA et retourne une analyse détaillée.
        
        Args:
            alert_data: Données de l'alerte à analyser
            
        Returns:
            Dict contenant l'analyse de l'alerte
        """
        try:
            # Construction du prompt pour l'IA
            prompt = self._build_analysis_prompt(alert_data)
            
            # Appel à l'API Gemini
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.api_url,
                    json={
                        "contents": [{
                            "role": "user",
                            "parts": [{"text": prompt}]
                        }]
                    },
                    timeout=60
                )
                response.raise_for_status()
                result = response.json()
                
                # Extraction de la réponse
                if result.get("candidates") and result["candidates"][0].get("content"):
                    text_response = result["candidates"][0]["content"]["parts"][0]["text"]
                    analysis = self._parse_ai_response(text_response)
                    return {
                        "success": True,
                        "analysis": analysis,
                        "raw_response": text_response
                    }
                else:
                    logger.error(f"Réponse inattendue de l'API Gemini: {result}")
                    return {
                        "success": False,
                        "error": "Réponse invalide de l'assistant IA"
                    }
                
        except httpx.HTTPStatusError as e:
            logger.error(f"Erreur HTTP de l'API Gemini: {e.response.status_code} - {e.response.text}")
            return {
                "success": False,
                "error": f"Erreur de communication avec l'assistant IA (Code: {e.response.status_code})"
            }
        except Exception as e:
            logger.error(f"Erreur lors de l'analyse de l'alerte: {str(e)}")
            return {
                "success": False,
                "error": "Une erreur interne est survenue lors de l'analyse IA"
            }
    
    def _build_analysis_prompt(self, alert_data: Dict[str, Any]) -> str:
        """Construit le prompt pour l'analyse de l'alerte."""
        return f"""
        Tu es un analyste expert en cybersécurité (DFIR/SOC) assistant un utilisateur de la plateforme Osiris.
        Une alerte a été générée. Voici les données de l'événement qui l'a déclenchée :

        Règle : {alert_data['rule_title']}
        Niveau : {alert_data['rule_level']}
        Date de détection : {alert_data['detected_at']}
        Statut : {alert_data['status']}

        Données de l'événement :
        {json.dumps(alert_data['event_data'], indent=2, ensure_ascii=False)}

        Fournis une analyse claire et concise en français, structurée exactement comme suit :

        ### Explication de l'Alerte
        [Explique en termes simples ce que l'alerte signifie]

        ### Évaluation du Risque Potentiel
        [Évalue le niveau de risque et justifie ton analyse]

        ### Étapes d'Investigation Recommandées
        [Liste numérotée d'actions concrètes à entreprendre]

        ### Requêtes OQL Suggérées
        [Liste de requêtes OQL pertinentes pour approfondir l'analyse]
        """
    
    def _parse_ai_response(self, response: str) -> Dict[str, Any]:
        """Parse la réponse de l'IA en une structure structurée."""
        sections = {
            "explication": "",
            "risque": "",
            "recommandations": [],
            "requetes_oql": []
        }
        
        current_section = None
        for line in response.split('\n'):
            line = line.strip()
            if not line:
                continue
            
            if "### Explication de l'Alerte" in line:
                current_section = "explication"
            elif "### Évaluation du Risque Potentiel" in line:
                current_section = "risque"
            elif "### Étapes d'Investigation Recommandées" in line:
                current_section = "recommandations"
            elif "### Requêtes OQL Suggérées" in line:
                current_section = "requetes_oql"
            elif current_section:
                if current_section in ["recommandations", "requetes_oql"]:
                    if line.startswith(("1.", "2.", "3.", "4.", "5.", "-")):
                        sections[current_section].append(line.lstrip("123456789.- "))
                else:
                    sections[current_section] += line + "\n"
        
        return sections 