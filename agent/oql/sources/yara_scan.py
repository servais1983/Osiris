import os
import glob
import logging
import yara
import hashlib
import math
from google.protobuf.struct_pb2 import Struct
from typing import Generator, Union, Dict, Any

logger = logging.getLogger(__name__)

class YaraRuleManager:
    """Gestionnaire de règles YARA avec support des règles externes et mise en cache."""
    
    def __init__(self):
        self._compiled_rules: Dict[str, yara.Rules] = {}
        self._rule_hashes: Dict[str, str] = {}
        
    def _calculate_hash(self, rule_content: str) -> str:
        """Calcule le hash SHA-256 d'une règle."""
        return hashlib.sha256(rule_content.encode()).hexdigest()
        
    def _compile_rule(self, rule_content: str) -> yara.Rules:
        """Compile une règle YARA avec gestion des erreurs."""
        try:
            return yara.compile(source=rule_content)
        except yara.SyntaxError as e:
            logger.error(f"Erreur de syntaxe dans la règle YARA : {e}")
            raise ValueError(f"Règle YARA invalide : {e}")
        except Exception as e:
            logger.error(f"Erreur lors de la compilation de la règle YARA : {e}")
            raise
            
    def get_rule(self, rule_content: str) -> yara.Rules:
        """Récupère une règle compilée, la compile si nécessaire."""
        rule_hash = self._calculate_hash(rule_content)
        
        if rule_hash not in self._compiled_rules:
            self._compiled_rules[rule_hash] = self._compile_rule(rule_content)
            self._rule_hashes[rule_hash] = rule_content
            
        return self._compiled_rules[rule_hash]
        
    def load_external_rule(self, rule_path: str) -> yara.Rules:
        """Charge et compile une règle depuis un fichier externe."""
        try:
            with open(rule_path, 'r', encoding='utf-8') as f:
                rule_content = f.read()
            return self.get_rule(rule_content)
        except Exception as e:
            logger.error(f"Erreur lors du chargement de la règle {rule_path} : {e}")
            raise

class YaraScanSource:
    """
    Source OQL pour le scan YARA des fichiers.
    Prend en paramètre un pattern de chemin (path_glob) et une règle YARA (rule_string ou rule_path).
    """
    def __init__(self, path_glob: str, rule: str, is_external: bool = False):
        if not path_glob:
            raise ValueError("Le paramètre path_glob est requis")
        if not rule:
            raise ValueError("Le paramètre rule est requis")
            
        self.path_glob = path_glob
        self.rule_manager = YaraRuleManager()
        
        try:
            # Chargement de la règle (interne ou externe)
            if is_external:
                self.rules = self.rule_manager.load_external_rule(rule)
                logger.info(f"Règle YARA externe chargée depuis : {rule}")
            else:
                self.rules = self.rule_manager.get_rule(rule)
                logger.info("Règle YARA interne chargée avec succès")
        except Exception as e:
            logger.error(f"Erreur lors du chargement de la règle YARA : {e}")
            raise

    def _calculate_file_entropy(self, file_path: str) -> float:
        """Calcule l'entropie de Shannon d'un fichier."""
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
            if not data:
                return 0.0
                
            entropy = 0
            for x in range(256):
                p_x = data.count(bytes([x])) / len(data)
                if p_x > 0:
                    entropy += -p_x * math.log2(p_x)
            return entropy
        except Exception as e:
            logger.error(f"Erreur lors du calcul de l'entropie de {file_path} : {e}")
            return 0.0

    def _calculate_file_hash(self, file_path: str) -> Dict[str, str]:
        """Calcule les hashs MD5, SHA1 et SHA256 d'un fichier."""
        hashes = {}
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
                
            hashes['md5'] = hashlib.md5(data).hexdigest()
            hashes['sha1'] = hashlib.sha1(data).hexdigest()
            hashes['sha256'] = hashlib.sha256(data).hexdigest()
        except Exception as e:
            logger.error(f"Erreur lors du calcul des hashs de {file_path} : {e}")
            
        return hashes

    def collect(self) -> Generator[Struct, None, None]:
        """
        Scanne les fichiers correspondant au pattern avec la règle YARA.
        Retourne les résultats détaillés pour chaque correspondance.
        """
        try:
            # Recherche des fichiers correspondant au pattern
            matching_files = glob.glob(self.path_glob, recursive=True)
            logger.info(f"Scan YARA : {len(matching_files)} fichiers trouvés pour le pattern {self.path_glob}")
            
            for file_path in matching_files:
                try:
                    # Vérification que c'est un fichier
                    if not os.path.isfile(file_path):
                        continue
                        
                    # Scan du fichier
                    matches = self.rules.match(file_path)
                    
                    if matches:
                        # Calcul des métadonnées du fichier
                        file_stats = os.stat(file_path)
                        file_entropy = self._calculate_file_entropy(file_path)
                        file_hashes = self._calculate_file_hash(file_path)
                        
                        for match in matches:
                            result = Struct()
                            
                            # Informations sur le fichier
                            result.update({
                                "file_path": file_path,
                                "file_size": file_stats.st_size,
                                "file_created": file_stats.st_ctime,
                                "file_modified": file_stats.st_mtime,
                                "file_accessed": file_stats.st_atime,
                                "file_entropy": file_entropy,
                                "file_hashes": file_hashes,
                                
                                # Informations sur la règle
                                "rule_name": match.rule,
                                "rule_tags": list(match.tags),
                                "rule_meta": dict(match.meta),
                                
                                # Détails des correspondances
                                "matches": [
                                    {
                                        "offset": m.offset,
                                        "matched_data": m.matched_data.hex(),
                                        "matched_length": m.matched_length,
                                        "matched_string": m.matched_string
                                    }
                                    for m in match.strings
                                ],
                                
                                # Statistiques
                                "match_count": len(match.strings),
                                "match_confidence": "High" if len(match.strings) > 2 else "Medium"
                            })
                            
                            yield result
                            
                except yara.Error as e:
                    logger.error(f"Erreur YARA lors du scan de {file_path} : {e}")
                    continue
                except Exception as e:
                    logger.error(f"Erreur lors du scan de {file_path} : {e}")
                    continue
                    
        except Exception as e:
            logger.error(f"Erreur lors de la collecte YARA : {e}")
            raise 