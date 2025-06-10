# 🏺 Osiris - Plateforme DFIR de Nouvelle Génération

![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-yellow.svg)
![Status](https://img.shields.io/badge/status-En%20Développement-orange.svg)

## 📋 Description

Osiris est une plateforme unifiée de Réponse à Incidents et d'Investigation Numérique (DFIR) qui combine les meilleures fonctionnalités des outils existants dans un écosystème cohérent et intelligent. La plateforme intègre la puissance de collecte de Velociraptor, les capacités de parsing de KAPE, et l'analyse approfondie d'Autopsy, le tout enrichi par une couche d'intelligence artificielle.

## ✨ Fonctionnalités Principales

### 🏗️ Architecture Hybride et Distribuée
- **Osiris Hive** : Serveur central déployable on-premise ou cloud
- **Osiris Agents** : Agents légers multi-plateformes (Windows, Linux, macOS)
- Communication sécurisée via gRPC sur TLS mutuel

### 🔍 Collecte Puissante via OQL
- **Osiris Query Language (OQL)** : Langage de requêtes unifié
- **Recettes de Collecte** : Bibliothèque modulaire d'artefacts forensiques
- Support des artefacts courants (Prefetch, Amcache, Shellbags, etc.)

### 🔄 Pipeline d'Analyse Automatisé
- Parsing automatisé des artefacts
- Normalisation des données (ECS)
- Enrichissement :
  - Threat Intelligence
  - Géolocalisation
  - Contexte Interne
- Moteurs de détection :
  - Règles Sigma
  - Règles YARA

### 🤖 Assistance par IA
- Détection d'anomalies
- Résumé d'incidents
- Assistance à l'investigation
- Traducteur OQL (langage naturel vers OQL)

### 🌐 Interface Web Moderne
- Tableau de bord global
- Gestion des agents
- Console de hunting OQL
- Timeline interactive
- Visualisations avancées
- Gestion de cas

## 🛠️ Stack Technologique

| Composant | Technologie | Justification |
|-----------|-------------|---------------|
| Backend | Python (FastAPI) / Go | Performance, asynchronisme |
| Base de Données | PostgreSQL + ClickHouse | Optimisé pour l'analytique |
| Frontend | React / TypeScript | Interface moderne et réactive |
| Communication | gRPC / Protobuf | Performance et efficacité |
| Agents | Python / Go | Multi-plateforme, léger |

## 🗺️ Roadmap

### Phase 1 : Le Cœur
- [ ] Agent de base (collecte simple)
- [ ] Serveur Hive avec gRPC
- [ ] Implémentation OQL

### Phase 2 : Intelligence de Collecte
- [ ] Enrichissement OQL
- [ ] Bibliothèque de Recettes
- [ ] Pipeline de parsing

### Phase 3 : Interface et Analyse
- [ ] Interface web React
- [ ] Timeline unifiée
- [ ] Moteurs Sigma/YARA

### Phase 4 : IA
- [ ] Enrichissement TI
- [ ] Détection d'anomalies
- [ ] Assistance IA

## 🚀 Installation

```bash
# Cloner le dépôt
git clone https://github.com/votre-org/osiris.git

# Accéder au répertoire
cd osiris

# Installer les dépendances
pip install -r requirements.txt
```

## 💻 Utilisation

```bash
# Démarrer le serveur Hive
python osiris_hive.py

# Démarrer un agent
python osiris_agent.py --server https://hive.example.com
```

## 🤝 Contribution

Les contributions sont les bienvenues ! Consultez notre [guide de contribution](CONTRIBUTING.md) pour plus de détails.

## 📄 Licence

Ce projet est sous licence MIT. Voir le fichier [LICENSE](LICENSE) pour plus de détails.

## 👥 Auteurs

- **Votre Nom** - *Travail initial* - [GitHub](https://github.com/votre-username)

## 🙏 Remerciements

- La communauté DFIR pour son inspiration
- Les projets open source qui ont inspiré Osiris
- Tous les contributeurs

## 📞 Support

Pour toute question ou problème :
- Ouvrir une issue sur GitHub
- Consulter la [documentation](docs/)
- Rejoindre notre [Discord](https://discord.gg/osiris)