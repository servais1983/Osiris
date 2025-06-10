-- Schéma de la base de données ClickHouse pour Osiris

-- Table des processus
CREATE TABLE IF NOT EXISTS processes (
    id UUID,
    agent_id UUID,
    pid UInt32,
    ppid UInt32,
    name String,
    command_line String,
    start_time DateTime,
    end_time DateTime,
    cpu_usage Float32,
    memory_usage UInt64,
    username String,
    integrity_level String,
    parent_name String,
    parent_command_line String,
    metadata String,
    created_at DateTime DEFAULT now()
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(created_at)
ORDER BY (agent_id, created_at, pid);

-- Table des fichiers
CREATE TABLE IF NOT EXISTS files (
    id UUID,
    agent_id UUID,
    path String,
    name String,
    extension String,
    size UInt64,
    created_time DateTime,
    modified_time DateTime,
    accessed_time DateTime,
    owner String,
    permissions String,
    md5 String,
    sha1 String,
    sha256 String,
    metadata String,
    created_at DateTime DEFAULT now()
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(created_at)
ORDER BY (agent_id, created_at, path);

-- Table des connexions réseau
CREATE TABLE IF NOT EXISTS network_connections (
    id UUID,
    agent_id UUID,
    local_address String,
    local_port UInt16,
    remote_address String,
    remote_port UInt16,
    protocol String,
    state String,
    pid UInt32,
    process_name String,
    created_at DateTime DEFAULT now()
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(created_at)
ORDER BY (agent_id, created_at, pid);

-- Table des événements du registre
CREATE TABLE IF NOT EXISTS registry_events (
    id UUID,
    agent_id UUID,
    key_path String,
    value_name String,
    value_type String,
    value_data String,
    event_type String,
    process_name String,
    pid UInt32,
    created_at DateTime DEFAULT now()
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(created_at)
ORDER BY (agent_id, created_at, key_path);

-- Table des événements Windows
CREATE TABLE IF NOT EXISTS windows_events (
    id UUID,
    agent_id UUID,
    event_id UInt32,
    event_type String,
    source String,
    level String,
    message String,
    time_created DateTime,
    process_id UInt32,
    thread_id UInt32,
    computer String,
    created_at DateTime DEFAULT now()
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(created_at)
ORDER BY (agent_id, created_at, event_id);

-- Table des scans YARA
CREATE TABLE IF NOT EXISTS yara_scans (
    id UUID,
    agent_id UUID,
    rule_name String,
    rule_namespace String,
    matched_file String,
    matched_strings String,
    metadata String,
    created_at DateTime DEFAULT now()
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(created_at)
ORDER BY (agent_id, created_at, rule_name);

-- Table des métriques système
CREATE TABLE IF NOT EXISTS system_metrics (
    id UUID,
    agent_id UUID,
    cpu_usage Float32,
    memory_usage Float32,
    disk_usage Float32,
    network_in UInt64,
    network_out UInt64,
    process_count UInt32,
    created_at DateTime DEFAULT now()
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(created_at)
ORDER BY (agent_id, created_at);

-- Table des journaux de l'agent
CREATE TABLE IF NOT EXISTS agent_logs (
    id UUID,
    agent_id UUID,
    level String,
    message String,
    component String,
    created_at DateTime DEFAULT now()
) ENGINE = MergeTree()
PARTITION BY toYYYYMM(created_at)
ORDER BY (agent_id, created_at, level);

-- Vues matérialisées pour les analyses courantes

-- Vue des processus suspects
CREATE MATERIALIZED VIEW IF NOT EXISTS suspicious_processes
ENGINE = MergeTree()
PARTITION BY toYYYYMM(created_at)
ORDER BY (agent_id, created_at)
AS SELECT
    id,
    agent_id,
    pid,
    name,
    command_line,
    start_time,
    username,
    integrity_level,
    metadata,
    created_at
FROM processes
WHERE
    name IN ('cmd.exe', 'powershell.exe', 'wmic.exe', 'net.exe', 'netstat.exe')
    OR command_line LIKE '% -enc %'
    OR command_line LIKE '% -e %'
    OR command_line LIKE '% -c %'
    OR command_line LIKE '% -w %'
    OR command_line LIKE '% -nop %';

-- Vue des connexions réseau suspectes
CREATE MATERIALIZED VIEW IF NOT EXISTS suspicious_connections
ENGINE = MergeTree()
PARTITION BY toYYYYMM(created_at)
ORDER BY (agent_id, created_at)
AS SELECT
    id,
    agent_id,
    local_address,
    local_port,
    remote_address,
    remote_port,
    protocol,
    state,
    pid,
    process_name,
    created_at
FROM network_connections
WHERE
    remote_port IN (4444, 8080, 8443)
    OR remote_address LIKE '%.onion'
    OR remote_address LIKE '%.tor2web'
    OR state = 'LISTENING'
    OR protocol = 'TCP';

-- Vue des modifications de registre suspectes
CREATE MATERIALIZED VIEW IF NOT EXISTS suspicious_registry
ENGINE = MergeTree()
PARTITION BY toYYYYMM(created_at)
ORDER BY (agent_id, created_at)
AS SELECT
    id,
    agent_id,
    key_path,
    value_name,
    value_type,
    value_data,
    event_type,
    process_name,
    pid,
    created_at
FROM registry_events
WHERE
    key_path LIKE '%\\Run%'
    OR key_path LIKE '%\\RunOnce%'
    OR key_path LIKE '%\\Policies%'
    OR key_path LIKE '%\\Services%'
    OR value_data LIKE '%powershell%'
    OR value_data LIKE '%cmd%'
    OR value_data LIKE '%wmic%'; 