from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
import asyncpg
import clickhouse_driver
from datetime import datetime

class StorageBackend(ABC):
    """Interface de base pour les backends de stockage"""
    
    @abstractmethod
    async def connect(self) -> None:
        """Établit la connexion avec le backend"""
        pass
    
    @abstractmethod
    async def disconnect(self) -> None:
        """Ferme la connexion avec le backend"""
        pass
    
    @abstractmethod
    async def execute_query(self, query: str, params: Optional[Dict] = None) -> List[Dict]:
        """Exécute une requête et retourne les résultats"""
        pass
    
    @abstractmethod
    async def insert_batch(self, table: str, data: List[Dict]) -> None:
        """Insère un lot de données"""
        pass

class PostgresBackend(StorageBackend):
    """Backend PostgreSQL pour les données relationnelles"""
    
    def __init__(self, dsn: str):
        self.dsn = dsn
        self.pool = None
    
    async def connect(self) -> None:
        self.pool = await asyncpg.create_pool(self.dsn)
    
    async def disconnect(self) -> None:
        if self.pool:
            await self.pool.close()
    
    async def execute_query(self, query: str, params: Optional[Dict] = None) -> List[Dict]:
        async with self.pool.acquire() as conn:
            return await conn.fetch(query, **(params or {}))
    
    async def insert_batch(self, table: str, data: List[Dict]) -> None:
        if not data:
            return
            
        columns = list(data[0].keys())
        values = [tuple(row[col] for col in columns) for row in data]
        
        query = f"""
            INSERT INTO {table} ({', '.join(columns)})
            VALUES ({', '.join(f'${i+1}' for i in range(len(columns)))})
        """
        
        async with self.pool.acquire() as conn:
            await conn.executemany(query, values)

class ClickHouseBackend(StorageBackend):
    """Backend ClickHouse pour les données de télémétrie"""
    
    def __init__(self, host: str, port: int, database: str, user: str, password: str):
        self.client = clickhouse_driver.Client(
            host=host,
            port=port,
            database=database,
            user=user,
            password=password
        )
    
    async def connect(self) -> None:
        # ClickHouse est sans état, pas besoin de connexion persistante
        pass
    
    async def disconnect(self) -> None:
        # ClickHouse est sans état, pas besoin de déconnexion
        pass
    
    async def execute_query(self, query: str, params: Optional[Dict] = None) -> List[Dict]:
        return self.client.execute(query, params or {})
    
    async def insert_batch(self, table: str, data: List[Dict]) -> None:
        if not data:
            return
            
        columns = list(data[0].keys())
        values = [tuple(row[col] for col in columns) for row in data]
        
        self.client.execute(
            f"INSERT INTO {table} ({', '.join(columns)}) VALUES",
            values
        )

class StorageManager:
    """Gestionnaire central du stockage"""
    
    def __init__(self):
        self.postgres: Optional[PostgresBackend] = None
        self.clickhouse: Optional[ClickHouseBackend] = None
    
    async def initialize(self, config: Dict[str, Any]) -> None:
        """Initialise les backends de stockage"""
        # PostgreSQL pour les données relationnelles
        self.postgres = PostgresBackend(config['postgres']['dsn'])
        await self.postgres.connect()
        
        # ClickHouse pour les données de télémétrie
        self.clickhouse = ClickHouseBackend(
            host=config['clickhouse']['host'],
            port=config['clickhouse']['port'],
            database=config['clickhouse']['database'],
            user=config['clickhouse']['user'],
            password=config['clickhouse']['password']
        )
        await self.clickhouse.connect()
    
    async def shutdown(self) -> None:
        """Ferme les connexions"""
        if self.postgres:
            await self.postgres.disconnect()
        if self.clickhouse:
            await self.clickhouse.disconnect()
    
    async def execute_oql(self, query: str, params: Optional[Dict] = None) -> List[Dict]:
        """Exécute une requête OQL en la distribuant sur les backends appropriés"""
        # TODO: Implémenter la logique de distribution des requêtes
        pass 