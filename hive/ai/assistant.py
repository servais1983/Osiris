from typing import Dict, Any
import re
from datetime import datetime

class Assistant:
    async def translate_to_oql(self, natural_language_query: str) -> Dict[str, Any]:
        """
        Traduit une requête en langage naturel en OQL.
        
        Args:
            natural_language_query: La requête en langage naturel
            
        Returns:
            Dict contenant la requête OQL et des métadonnées
        """
        try:
            # Construction du prompt
            prompt = f"""
            {self.system_prompts['oql_translator']}
            
            Requête à traduire :
            {natural_language_query}
            
            Fournis uniquement la requête OQL avec ses commentaires, sans autre texte.
            """
            
            # Appel à l'API
            response = await self._call_gemini_api(prompt)
            
            # Extraction de la requête OQL
            oql_query = self._extract_oql_query(response)
            
            # Validation de la requête
            if not self._validate_oql_query(oql_query):
                raise ValueError("La requête OQL générée n'est pas valide")
            
            return {
                "success": True,
                "query": oql_query,
                "natural_language": natural_language_query,
                "timestamp": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Erreur lors de la traduction en OQL: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def _extract_oql_query(self, response: str) -> str:
        """Extrait la requête OQL de la réponse de l'IA."""
        # Recherche du bloc de code OQL
        oql_match = re.search(r'```oql\n(.*?)\n```', response, re.DOTALL)
        if oql_match:
            return oql_match.group(1).strip()
        
        # Si pas de bloc de code, on prend tout le texte
        return response.strip()
    
    def _validate_oql_query(self, query: str) -> bool:
        """Valide la syntaxe de la requête OQL."""
        # Vérifications basiques
        if not query:
            return False
            
        # Vérifie la présence des mots-clés essentiels
        required_keywords = ['SELECT', 'FROM']
        if not all(keyword in query.upper() for keyword in required_keywords):
            return False
            
        # Vérifie la structure de base
        try:
            # Extraction des clauses principales
            select_match = re.search(r'SELECT\s+(.*?)\s+FROM', query, re.IGNORECASE)
            from_match = re.search(r'FROM\s+(.*?)(?:\s+WHERE|\s+GROUP BY|\s+ORDER BY|$)', query, re.IGNORECASE)
            
            if not (select_match and from_match):
                return False
                
            # Vérifie la présence de WHERE si nécessaire
            if 'WHERE' in query.upper():
                where_match = re.search(r'WHERE\s+(.*?)(?:\s+GROUP BY|\s+ORDER BY|$)', query, re.IGNORECASE)
                if not where_match:
                    return False
            
            return True
            
        except Exception:
            return False 