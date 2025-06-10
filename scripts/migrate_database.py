import asyncio
import sqlite3
import asyncpg
import clickhouse_driver
from datetime import datetime
import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
import os
from dotenv import load_dotenv

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Chargement des variables d'environnement
load_dotenv()

class DatabaseMigrator:
    """Gestionnaire de migration des bases de données"""
    
    def __init__(self):
        self.sqlite_conn = None
        self.postgres_pool = None
        self.clickhouse_client = None
        
    async def connect(self):
        """Établit les connexions aux bases de données"""
        # Connexion SQLite
        self.sqlite_conn = sqlite3.connect('hive.db')
        self.sqlite_conn.row_factory = sqlite3.Row
        
        # Connexion PostgreSQL
        self.postgres_pool = await asyncpg.create_pool(
            dsn=os.getenv('POSTGRES_DSN'),
            min_size=5,
            max_size=20
        )
        
        # Connexion ClickHouse
        self.clickhouse_client = clickhouse_driver.Client(
            host=os.getenv('CLICKHOUSE_HOST'),
            port=int(os.getenv('CLICKHOUSE_PORT', 9000)),
            database=os.getenv('CLICKHOUSE_DB'),
            user=os.getenv('CLICKHOUSE_USER'),
            password=os.getenv('CLICKHOUSE_PASSWORD')
        )
    
    async def close(self):
        """Ferme les connexions"""
        if self.sqlite_conn:
            self.sqlite_conn.close()
        if self.postgres_pool:
            await self.postgres_pool.close()
    
    async def migrate_cases(self):
        """Migre les cas d'investigation"""
        logger.info("Migration des cas d'investigation...")
        
        # Récupération des cas depuis SQLite
        cursor = self.sqlite_conn.cursor()
        cursor.execute("SELECT * FROM cases")
        cases = cursor.fetchall()
        
        # Migration vers PostgreSQL
        async with self.postgres_pool.acquire() as conn:
            for case in cases:
                await conn.execute("""
                    INSERT INTO cases (
                        id, title, description, created_by,
                        created_at, updated_at, status, tags
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                    ON CONFLICT (id) DO UPDATE SET
                        title = EXCLUDED.title,
                        description = EXCLUDED.description,
                        status = EXCLUDED.status,
                        tags = EXCLUDED.tags,
                        updated_at = EXCLUDED.updated_at
                """, (
                    case['id'],
                    case['title'],
                    case['description'],
                    case['created_by'],
                    case['created_at'],
                    case['updated_at'],
                    case['status'],
                    case['tags'].split(',') if case['tags'] else []
                ))
        
        logger.info(f"{len(cases)} cas migrés")
    
    async def migrate_alerts(self):
        """Migre les alertes"""
        logger.info("Migration des alertes...")
        
        # Récupération des alertes depuis SQLite
        cursor = self.sqlite_conn.cursor()
        cursor.execute("SELECT * FROM alerts")
        alerts = cursor.fetchall()
        
        # Migration vers PostgreSQL
        async with self.postgres_pool.acquire() as conn:
            for alert in alerts:
                await conn.execute("""
                    INSERT INTO alerts (
                        id, case_id, title, description,
                        severity, status, source, created_at,
                        updated_at, metadata
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                    ON CONFLICT (id) DO UPDATE SET
                        title = EXCLUDED.title,
                        description = EXCLUDED.description,
                        severity = EXCLUDED.severity,
                        status = EXCLUDED.status,
                        metadata = EXCLUDED.metadata,
                        updated_at = EXCLUDED.updated_at
                """, (
                    alert['id'],
                    alert['case_id'],
                    alert['title'],
                    alert['description'],
                    alert['severity'],
                    alert['status'],
                    alert['source'],
                    alert['created_at'],
                    alert['updated_at'],
                    json.loads(alert['metadata']) if alert['metadata'] else {}
                ))
        
        logger.info(f"{len(alerts)} alertes migrées")
    
    async def migrate_processes(self):
        """Migre les données de processus"""
        logger.info("Migration des processus...")
        
        # Récupération des processus depuis SQLite
        cursor = self.sqlite_conn.cursor()
        cursor.execute("SELECT * FROM processes")
        processes = cursor.fetchall()
        
        # Migration vers ClickHouse
        for process in processes:
            self.clickhouse_client.execute(
                """
                INSERT INTO processes (
                    id, agent_id, pid, ppid, name,
                    command_line, start_time, end_time,
                    cpu_usage, memory_usage, username,
                    integrity_level, parent_name,
                    parent_command_line, metadata, created_at
                ) VALUES
                """,
                [(
                    process['id'],
                    process['agent_id'],
                    process['pid'],
                    process['ppid'],
                    process['name'],
                    process['command_line'],
                    process['start_time'],
                    process['end_time'],
                    process['cpu_usage'],
                    process['memory_usage'],
                    process['username'],
                    process['integrity_level'],
                    process['parent_name'],
                    process['parent_command_line'],
                    process['metadata'],
                    process['created_at']
                )]
            )
        
        logger.info(f"{len(processes)} processus migrés")
    
    async def migrate_network_connections(self):
        """Migre les connexions réseau"""
        logger.info("Migration des connexions réseau...")
        
        # Récupération des connexions depuis SQLite
        cursor = self.sqlite_conn.cursor()
        cursor.execute("SELECT * FROM network_connections")
        connections = cursor.fetchall()
        
        # Migration vers ClickHouse
        for conn in connections:
            self.clickhouse_client.execute(
                """
                INSERT INTO network_connections (
                    id, agent_id, local_address, local_port,
                    remote_address, remote_port, protocol,
                    state, pid, process_name, created_at
                ) VALUES
                """,
                [(
                    conn['id'],
                    conn['agent_id'],
                    conn['local_address'],
                    conn['local_port'],
                    conn['remote_address'],
                    conn['remote_port'],
                    conn['protocol'],
                    conn['state'],
                    conn['pid'],
                    conn['process_name'],
                    conn['created_at']
                )]
            )
        
        logger.info(f"{len(connections)} connexions réseau migrées")
    
    async def migrate_files(self):
        """Migre les données de fichiers"""
        logger.info("Migration des fichiers...")
        
        # Récupération des fichiers depuis SQLite
        cursor = self.sqlite_conn.cursor()
        cursor.execute("SELECT * FROM files")
        files = cursor.fetchall()
        
        # Migration vers ClickHouse
        for file in files:
            self.clickhouse_client.execute(
                """
                INSERT INTO files (
                    id, agent_id, path, name, extension,
                    size, created_time, modified_time,
                    accessed_time, owner, permissions,
                    md5, sha1, sha256, metadata, created_at
                ) VALUES
                """,
                [(
                    file['id'],
                    file['agent_id'],
                    file['path'],
                    file['name'],
                    file['extension'],
                    file['size'],
                    file['created_time'],
                    file['modified_time'],
                    file['accessed_time'],
                    file['owner'],
                    file['permissions'],
                    file['md5'],
                    file['sha1'],
                    file['sha256'],
                    file['metadata'],
                    file['created_at']
                )]
            )
        
        logger.info(f"{len(files)} fichiers migrés")

async def main():
    """Point d'entrée principal"""
    migrator = DatabaseMigrator()
    
    try:
        # Connexion aux bases de données
        await migrator.connect()
        
        # Migration des données
        await migrator.migrate_cases()
        await migrator.migrate_alerts()
        await migrator.migrate_processes()
        await migrator.migrate_network_connections()
        await migrator.migrate_files()
        
        logger.info("Migration terminée avec succès")
        
    except Exception as e:
        logger.error(f"Erreur lors de la migration: {e}")
        raise
        
    finally:
        await migrator.close()

if __name__ == '__main__':
    asyncio.run(main()) 