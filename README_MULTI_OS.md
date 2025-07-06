# Osiris - Collecteur Forensique Multi-OS

## Vue d'ensemble

Osiris est un collecteur forensique avancé conçu pour fonctionner sur **Windows**, **Linux** et **macOS**. Le projet garantit une portabilité totale grâce à une architecture modulaire et des tests multi-OS robustes.

## Architecture Multi-OS

### Collecteurs par Plateforme

- **Windows** : `collectors/windows/` - Collecteurs spécifiques à Windows
- **Linux** : `collectors/linux/` - Collecteurs spécifiques à Linux  
- **macOS** : `collectors/macos/` - Collecteurs spécifiques à macOS

### Gestion de la Portabilité

#### 1. Imports Conditionnels
Les modules utilisent des imports conditionnels pour gérer les dépendances spécifiques à chaque OS :

```python
# Exemple dans collectors/linux/base.py
try:
    import pwd
    import grp
    PWD_AVAILABLE = True
except ImportError:
    PWD_AVAILABLE = False
    # Mock pour les tests sur Windows
    pwd = MockPwd()
    grp = None
```

#### 2. Vérifications de Disponibilité
Chaque collecteur vérifie la disponibilité des fonctionnalités avant de les utiliser :

```python
def _check_psutil_availability(self) -> bool:
    """Vérifie si psutil est disponible"""
    try:
        import psutil
        return True
    except ImportError:
        self.logger.warning("Module psutil non disponible sur ce système.")
        return False
```

#### 3. Méthodes Utilitaires Multi-OS
Les collecteurs utilisent des méthodes utilitaires pour les fonctions spécifiques à l'OS :

```python
def _geteuid(self):
    """Méthode utilitaire multi-OS"""
    try:
        return os.geteuid()
    except AttributeError:
        return 0  # Par défaut, root sur Windows ou OS sans geteuid
```

## Tests Multi-OS

### Configuration des Tests

Le fichier `tests/conftest.py` configure automatiquement l'environnement de test selon l'OS :

- **Windows** : Mock des modules Unix (`pwd`, `grp`, `fcntl`, etc.)
- **Linux/macOS** : Mock des modules Windows (`winreg`, `win32api`, etc.)
- **Fonctions manquantes** : Mock automatique de `os.geteuid()`, `os.getuid()`, etc.

### Types de Tests

#### 1. Tests Multi-OS (`tests/test_linux_multi_os.py`)
- Fonctionnent sur tous les OS
- Vérifient la structure des données retournées
- Testent la gestion des erreurs et des fonctionnalités non disponibles

#### 2. Tests Spécifiques à l'OS
- Utilisent le décorateur `@skip_if_not_linux()` pour les tests Linux-only
- Testent les fonctionnalités réelles sur l'OS cible
- Vérifient l'intégration avec les APIs système

### Exécution des Tests

```bash
# Tests multi-OS (fonctionnent partout)
python -m pytest tests/test_linux_multi_os.py -v

# Tests avec couverture
python -m pytest tests/test_linux_multi_os.py -v --cov=collectors.linux --cov-report=term-missing

# Tous les tests
python -m pytest tests/ -v --cov=collectors --cov-report=term-missing
```

## Fonctionnalités par OS

### Windows
- ✅ Collecteurs Windows Registry
- ✅ Collecteurs Windows Event Logs
- ✅ Collecteurs Windows Services
- ✅ Collecteurs Windows Processes
- ✅ Tests multi-OS fonctionnels

### Linux
- ✅ Collecteurs Linux Users/Groups
- ✅ Collecteurs Linux System Logs
- ✅ Collecteurs Linux Processes
- ✅ Collecteurs Linux Network
- ✅ Collecteurs Linux Files
- ✅ Collecteurs Linux Services (systemd)
- ✅ Collecteurs Linux Cron Jobs
- ✅ Tests multi-OS fonctionnels

### macOS
- ✅ Collecteurs macOS (structure en place)
- ✅ Tests multi-OS fonctionnels
- 🔄 Collecteurs spécifiques en développement

## Gestion des Erreurs Multi-OS

### Stratégies de Fallback

1. **Fonctionnalités non disponibles** : Retour de résultats vides avec logs d'avertissement
2. **Modules manquants** : Mock automatique pour les tests
3. **Fichiers système absents** : Vérification d'existence avant lecture
4. **Commandes système non disponibles** : Vérification de disponibilité avant exécution

### Exemple de Gestion d'Erreur

```python
def _collect_users(self) -> List[Dict[str, Any]]:
    """Collecte les informations sur les utilisateurs"""
    users = []
    
    try:
        # Lire /etc/passwd si dispo
        if os.path.exists('/etc/passwd'):
            with open('/etc/passwd', 'r') as f:
                # ... traitement ...
        else:
            self.logger.warning("/etc/passwd non disponible sur ce système.")
            return users
    except Exception as e:
        self.logger.error(f"Erreur lors de la collecte des utilisateurs: {e}")
    
    return users
```

## Installation et Utilisation

### Prérequis

```bash
# Installation des dépendances
pip install -r requirements.txt

# Installation en mode développement
pip install -e .
```

### Utilisation

```python
from collectors.linux import LinuxCollectorManager

# Créer le gestionnaire
manager = LinuxCollectorManager()

# Lister les collecteurs disponibles
collectors = manager.list_collectors()

# Exécuter un collecteur spécifique
collector = manager.get_collector('users')
result = collector.collect()

# Exécuter tous les collecteurs
results = manager.collect_all()
```

### Exécution Multi-OS

Le même code fonctionne sur tous les OS :

```python
# Sur Windows
from collectors.windows import WindowsCollectorManager
manager = WindowsCollectorManager()

# Sur Linux
from collectors.linux import LinuxCollectorManager  
manager = LinuxCollectorManager()

# Sur macOS
from collectors.macos import MacOSCollectorManager
manager = MacOSCollectorManager()
```

## Couverture de Code

### Objectifs de Couverture

- **Windows** : > 80% de couverture
- **Linux** : > 70% de couverture  
- **macOS** : > 60% de couverture
- **Tests Multi-OS** : 100% de passage sur tous les OS

### Génération des Rapports

```bash
# Couverture complète
python -m pytest tests/ --cov=collectors --cov-report=html --cov-report=term-missing

# Couverture par plateforme
python -m pytest tests/test_linux_multi_os.py --cov=collectors.linux --cov-report=html
python -m pytest tests/test_windows_multi_os.py --cov=collectors.windows --cov-report=html
```

## Contribution

### Ajout de Nouveaux Collecteurs

1. **Créer le collecteur** dans le dossier approprié (`collectors/{os}/`)
2. **Implémenter les vérifications de disponibilité**
3. **Ajouter les tests multi-OS** dans `tests/test_{os}_multi_os.py`
4. **Vérifier la portabilité** sur tous les OS

### Bonnes Pratiques

- ✅ Utiliser des imports conditionnels
- ✅ Vérifier la disponibilité des fonctionnalités
- ✅ Gérer les erreurs gracieusement
- ✅ Logger les fonctionnalités non disponibles
- ✅ Tester sur tous les OS
- ❌ Ne jamais supposer la présence de modules/fichiers spécifiques à l'OS

## Support

- **Issues** : Signaler les problèmes de portabilité
- **Tests** : Vérifier que les tests passent sur votre OS
- **Documentation** : Mettre à jour ce README si nécessaire

---

**Osiris** - Collecteur Forensique Multi-OS | Compatible Windows, Linux, macOS 