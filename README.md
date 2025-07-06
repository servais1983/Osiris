# Osiris - Collecteur Forensique Multi-OS

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platforms: Windows, Linux, macOS](https://img.shields.io/badge/platforms-Windows%20%7C%20Linux%20%7C%20macOS-green.svg)](https://github.com/your-repo/osiris)

**Osiris** est un collecteur forensique multi-OS robuste et portable, conçu pour collecter des artefacts forensiques sur Windows, Linux et macOS, même en l'absence de modules natifs spécifiques à la plateforme.

## 🌟 Fonctionnalités Principales

### ✅ Portabilité Multi-OS
- **Windows** : Collecteurs pour processus, services, registre, événements, réseau, fichiers, utilisateurs, historique navigateur
- **Linux** : Collecteurs pour processus, services, logs système, historique shell, réseau, fichiers, utilisateurs
- **macOS** : Collecteurs pour logs unifiés et persistance

### ✅ Robustesse et Fiabilité
- **Gestion d'erreurs avancée** : Chaque collecteur retourne toujours une structure de données cohérente
- **Mode dégradé** : Fonctionne même sans privilèges administrateur (données limitées)
- **Imports conditionnels** : Gère automatiquement les modules manquants
- **Tests multi-OS** : Validation automatique sur toutes les plateformes

### ✅ Architecture Modulaire
- **Gestionnaire universel** : Interface unifiée pour tous les collecteurs
- **Structure homogène** : Format de sortie JSON standardisé
- **Extensibilité** : Ajout facile de nouveaux collecteurs

## 🚀 Installation Rapide

### Prérequis
```bash
Python 3.8+
```

### Installation
```bash
git clone https://github.com/your-repo/osiris.git
cd osiris
pip install -r requirements.txt
```

### Dépendances Optionnelles
```bash
# Windows
pip install pywin32 psutil

# Linux
pip install psutil

# macOS
pip install psutil
```

## 📖 Utilisation

### Interface en Ligne de Commande

```bash
# Informations système
python osiris_cli.py --system-info

# Liste des collecteurs disponibles
python osiris_cli.py --list

# Collecte d'un artefact spécifique
python osiris_cli.py --collect users --output results.json

# Collecte de tous les artefacts
python osiris_cli.py --collect-all --output full_scan.json

# Collecte pour une plateforme spécifique
python osiris_cli.py --platform windows --collect processes
```

### Utilisation Programmée

```python
from collectors import collect_all, collect_specific, list_collectors

# Collecte tous les artefacts
results = collect_all()

# Collecte d'un artefact spécifique
users_data = collect_specific('windows', 'users')

# Liste des collecteurs disponibles
collectors = list_collectors()
```

## 🔧 Architecture

### Structure des Collecteurs

```
collectors/
├── __init__.py              # Gestionnaire universel
├── windows/                 # Collecteurs Windows
│   ├── base.py             # Classe de base Windows
│   ├── processes.py        # Collecteur de processus
│   ├── services.py         # Collecteur de services
│   ├── registry.py         # Collecteur de registre
│   ├── events.py           # Collecteur d'événements
│   ├── network.py          # Collecteur réseau
│   ├── files.py            # Collecteur de fichiers
│   ├── users.py            # Collecteur d'utilisateurs
│   └── browser_history.py  # Collecteur d'historique navigateur
├── linux/                   # Collecteurs Linux
│   ├── base.py             # Classe de base Linux
│   ├── processes.py        # Collecteur de processus
│   ├── services.py         # Collecteur de services
│   ├── system_logs.py      # Collecteur de logs système
│   ├── shell_history.py    # Collecteur d'historique shell
│   ├── network.py          # Collecteur réseau
│   ├── files.py            # Collecteur de fichiers
│   └── users.py            # Collecteur d'utilisateurs
└── macos/                   # Collecteurs macOS
    ├── unified_logs.py     # Collecteur de logs unifiés
    └── persistence.py      # Collecteur de persistance
```

### Format de Sortie Standard

Tous les collecteurs retournent une structure JSON homogène :

```json
{
  "system_info": {
    "platform": "win32",
    "hostname": "COMPUTER-NAME",
    "current_user": "username",
    "is_admin": false
  },
  "data": {
    // Données spécifiques au collecteur
  },
  "summary": {
    "total_items": 42,
    "timestamp": "2025-07-06T22:30:00",
    "mode": "full|degraded"
  },
  "error": null  // ou message d'erreur si applicable
}
```

## 🧪 Tests et Validation

### Test Simple
```bash
python test_osiris_simple.py
```

### Test Complet
```bash
python test_osiris_complete.py
```

### Tests Multi-OS
```bash
# Tests Windows
python -m pytest tests/test_windows_*.py

# Tests Linux
python -m pytest tests/test_linux_*.py

# Tests macOS
python -m pytest tests/test_macos_*.py
```

## 🔒 Sécurité et Privilèges

### Windows
- **Mode complet** : Privilèges administrateur requis
- **Mode dégradé** : Fonctionne avec privilèges utilisateur standard
- **Collecteurs sensibles** : Services, registre, événements système

### Linux
- **Mode complet** : Privilèges root requis
- **Mode dégradé** : Fonctionne avec privilèges utilisateur
- **Collecteurs sensibles** : Services système, logs d'authentification

### macOS
- **Mode complet** : Privilèges administrateur requis
- **Mode dégradé** : Fonctionne avec privilèges utilisateur
- **Collecteurs sensibles** : Logs unifiés, persistance système

## 📝 Ajout d'un Nouveau Collecteur

### 1. Créer le Collecteur
```python
# collectors/windows/my_collector.py
from .base import WindowsCollector

class MyCollector(WindowsCollector):
    def _collect(self) -> Dict[str, Any]:
        results = {
            'system_info': self.get_system_info(),
            'my_data': [],
            'summary': {}
        }
        
        try:
            # Logique de collecte
            results['my_data'] = self._collect_my_data()
            results['summary'] = self._generate_summary(results)
        except Exception as e:
            results['error'] = str(e)
        
        return results
```

### 2. Enregistrer le Collecteur
```python
# collectors/windows/__init__.py
from .my_collector import MyCollector

class WindowsCollectorManager:
    def __init__(self):
        self.collectors = {
            # ... autres collecteurs
            'my_collector': MyCollector
        }
```

## 🐛 Dépannage

### Erreurs Courantes

#### Module 'win32xxx' has no attribute 'XXX'
**Solution** : Les modules pywin32 peuvent avoir des versions différentes. Osiris gère automatiquement ces cas avec des fallbacks.

#### Privilèges insuffisants
**Solution** : Exécutez en tant qu'administrateur pour une collecte complète, ou utilisez le mode dégradé.

#### Collecteur non trouvé
**Solution** : Vérifiez la liste des collecteurs avec `python osiris_cli.py --list`

### Logs et Debug
```bash
# Mode verbeux
python osiris_cli.py --collect users --verbose

# Logs détaillés
export OSIRIS_LOG_LEVEL=DEBUG
python osiris_cli.py --collect-all
```

## 🤝 Contribution

1. Fork le projet
2. Créez une branche feature (`git checkout -b feature/AmazingFeature`)
3. Commit vos changements (`git commit -m 'Add some AmazingFeature'`)
4. Push vers la branche (`git push origin feature/AmazingFeature`)
5. Ouvrez une Pull Request

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

## 🙏 Remerciements

- **pywin32** : Modules Windows
- **psutil** : Informations système cross-platform
- **pytest** : Framework de tests

## 📞 Support

- **Issues** : [GitHub Issues](https://github.com/your-repo/osiris/issues)
- **Documentation** : [Wiki](https://github.com/your-repo/osiris/wiki)
- **Email** : support@osiris-forensics.com

## 🛡️ Robustesse, gestion des erreurs et mode dégradé

Osiris est conçu pour **ne jamais bloquer la collecte**, même si certaines commandes ou modules sont absents ou si les privilèges sont insuffisants.

- **Gestion d'erreur avancée** :
  - Toutes les erreurs (commandes manquantes, modules non trouvés, accès refusé) sont loguées dans `osiris.log` et affichées en mode verbeux.
  - Les erreurs critiques n'arrêtent jamais la collecte : Osiris continue avec ce qui est disponible.
  - Les collecteurs non implémentés affichent un avertissement mais ne bloquent pas le scan.

- **Mode dégradé** :
  - Si un artefact ne peut pas être collecté (ex : pas admin, commande absente), Osiris passe automatiquement en mode dégradé pour ce collecteur.
  - Les résultats partiels sont toujours sauvegardés, avec une indication claire du mode (`"mode": "degraded"`).

- **Philosophie** :
  - Osiris privilégie la **résilience** : il collecte tout ce qu'il peut, informe sur ce qui manque, mais ne s'arrête jamais brutalement.
  - Les messages d'erreur sont là pour la transparence, pas pour bloquer l'utilisateur.

**Exemple de résultat en mode dégradé** :
```json
{
  "system_info": { ... },
  "data": { ... },
  "summary": {
    "mode": "degraded",
    ...
  },
  "error": "Commande net user absente"
}
```

Pour une collecte complète, exécutez Osiris en tant qu'administrateur ou sur une version de Windows avec toutes les commandes système disponibles.

---

**Osiris** - Collecteur forensique multi-OS robuste et portable 🚀