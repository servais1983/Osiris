-- Schéma de la base de données PostgreSQL pour Osiris

-- Extension pour les UUID
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Table des cas d'investigation
CREATE TABLE IF NOT EXISTS cases (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    title VARCHAR(255) NOT NULL,
    description TEXT,
    created_by VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) NOT NULL DEFAULT 'open',
    tags TEXT[] DEFAULT '{}',
    tenant_id INTEGER NOT NULL DEFAULT 1
);

-- Table des notes de cas
CREATE TABLE IF NOT EXISTS case_notes (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    case_id UUID REFERENCES cases(id) ON DELETE CASCADE,
    content TEXT NOT NULL,
    author VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    tenant_id INTEGER NOT NULL DEFAULT 1
);

-- Table des requêtes de cas
CREATE TABLE IF NOT EXISTS case_queries (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    case_id UUID REFERENCES cases(id) ON DELETE CASCADE,
    query TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Table des résultats de requêtes
CREATE TABLE IF NOT EXISTS case_results (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    case_id UUID REFERENCES cases(id) ON DELETE CASCADE,
    query_id UUID REFERENCES case_queries(id) ON DELETE CASCADE,
    result JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Table des alertes
CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    case_id UUID REFERENCES cases(id) ON DELETE CASCADE,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'new',
    source VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    metadata JSONB DEFAULT '{}'
);

-- Table des agents
CREATE TABLE IF NOT EXISTS agents (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    hostname VARCHAR(255) NOT NULL,
    ip_address INET NOT NULL,
    os_type VARCHAR(50) NOT NULL,
    os_version VARCHAR(255) NOT NULL,
    last_seen TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(50) NOT NULL DEFAULT 'active',
    metadata JSONB DEFAULT '{}'
);

-- Table des collectes
CREATE TABLE IF NOT EXISTS collections (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    agent_id UUID REFERENCES agents(id) ON DELETE CASCADE,
    type VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    started_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP WITH TIME ZONE,
    metadata JSONB DEFAULT '{}'
);

-- Table des utilisateurs
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'analyst',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP WITH TIME ZONE,
    is_active BOOLEAN DEFAULT TRUE,
    tenant_id INTEGER NOT NULL DEFAULT 1
);

-- Table des sessions
CREATE TABLE IF NOT EXISTS sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    ip_address INET,
    user_agent TEXT
);

-- Table pour l'historique des actions de réponse
CREATE TABLE response_actions_log (
    id SERIAL PRIMARY KEY,
    tenant_id INTEGER NOT NULL DEFAULT 1,
    case_id INTEGER REFERENCES cases(id),
    playbook_name VARCHAR(255),
    action_name VARCHAR(100) NOT NULL,
    target_agent_id VARCHAR(255),
    parameters JSONB,
    status VARCHAR(50) NOT NULL, -- 'Success', 'Failure', 'Dry Run'
    execution_time_ms INTEGER,
    message TEXT,
    executed_at TIMESTAMPTZ DEFAULT NOW()
);

-- Table pour les profils comportementaux des utilisateurs
CREATE TABLE user_behavior_profiles (
    id SERIAL PRIMARY KEY,
    tenant_id INTEGER NOT NULL DEFAULT 1,
    user_id VARCHAR(255) NOT NULL,
    profile_data JSONB NOT NULL,
    last_updated TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id, user_id)
);

-- Table pour les profils comportementaux des hôtes
CREATE TABLE host_behavior_profiles (
    id SERIAL PRIMARY KEY,
    tenant_id INTEGER NOT NULL DEFAULT 1,
    host_id VARCHAR(255) NOT NULL,
    profile_data JSONB NOT NULL,
    last_updated TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id, host_id)
);

-- Table pour les scores de risque des utilisateurs
CREATE TABLE user_risk_scores (
    id SERIAL PRIMARY KEY,
    tenant_id INTEGER NOT NULL DEFAULT 1,
    user_id VARCHAR(255) NOT NULL,
    risk_score INTEGER NOT NULL DEFAULT 0,
    risk_level VARCHAR(50) NOT NULL DEFAULT 'normal',
    last_updated TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(tenant_id, user_id)
);

-- Table pour les alertes critiques
CREATE TABLE critical_alerts (
    id SERIAL PRIMARY KEY,
    tenant_id INTEGER NOT NULL DEFAULT 1,
    user_id VARCHAR(255) NOT NULL,
    alert_type VARCHAR(100) NOT NULL,
    risk_score INTEGER NOT NULL,
    alert_data JSONB,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    status VARCHAR(50) DEFAULT 'open'
);

-- Table pour les playbooks d'automatisation
CREATE TABLE automation_playbooks (
    id SERIAL PRIMARY KEY,
    tenant_id INTEGER NOT NULL DEFAULT 1,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    trigger_config JSONB,
    sequence_config JSONB,
    settings JSONB,
    enabled BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Table pour les indicateurs de threat intelligence
CREATE TABLE threat_intel_indicators (
    id SERIAL PRIMARY KEY,
    tenant_id INTEGER NOT NULL DEFAULT 1,
    indicator_type VARCHAR(50) NOT NULL, -- 'ip', 'hash', 'url', 'domain'
    indicator_value TEXT NOT NULL,
    source VARCHAR(255),
    metadata JSONB,
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    UNIQUE(tenant_id, indicator_type, indicator_value)
);

-- Index pour améliorer les performances
CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
CREATE INDEX IF NOT EXISTS idx_cases_created_at ON cases(created_at);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_agents_last_seen ON agents(last_seen);
CREATE INDEX IF NOT EXISTS idx_collections_status ON collections(status);
CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX idx_cases_tenant_status ON cases(tenant_id, status);
CREATE INDEX idx_response_log_tenant_time ON response_actions_log(tenant_id, executed_at);
CREATE INDEX idx_user_profiles_tenant_user ON user_behavior_profiles(tenant_id, user_id);
CREATE INDEX idx_host_profiles_tenant_host ON host_behavior_profiles(tenant_id, host_id);
CREATE INDEX idx_risk_scores_tenant_level ON user_risk_scores(tenant_id, risk_level);
CREATE INDEX idx_critical_alerts_tenant_status ON critical_alerts(tenant_id, status);
CREATE INDEX idx_playbooks_tenant_enabled ON automation_playbooks(tenant_id, enabled);
CREATE INDEX idx_threat_intel_tenant_type ON threat_intel_indicators(tenant_id, indicator_type);

-- Fonction pour mettre à jour le timestamp updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Triggers pour mettre à jour updated_at
CREATE TRIGGER update_cases_updated_at
    BEFORE UPDATE ON cases
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_alerts_updated_at
    BEFORE UPDATE ON alerts
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- Fonction pour mettre à jour automatiquement updated_at
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Trigger pour automation_playbooks
CREATE TRIGGER update_automation_playbooks_updated_at 
    BEFORE UPDATE ON automation_playbooks 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- Fonction pour nettoyer les indicateurs expirés
CREATE OR REPLACE FUNCTION cleanup_expired_indicators()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM threat_intel_indicators 
    WHERE expires_at IS NOT NULL AND expires_at < NOW();
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Fonction pour calculer les statistiques de risque par tenant
CREATE OR REPLACE FUNCTION get_risk_statistics(p_tenant_id INTEGER)
RETURNS TABLE(
    total_users INTEGER,
    critical_users INTEGER,
    high_users INTEGER,
    medium_users INTEGER,
    low_users INTEGER,
    normal_users INTEGER,
    avg_risk_score NUMERIC
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        COUNT(*)::INTEGER as total_users,
        COUNT(CASE WHEN risk_level = 'critical' THEN 1 END)::INTEGER as critical_users,
        COUNT(CASE WHEN risk_level = 'high' THEN 1 END)::INTEGER as high_users,
        COUNT(CASE WHEN risk_level = 'medium' THEN 1 END)::INTEGER as medium_users,
        COUNT(CASE WHEN risk_level = 'low' THEN 1 END)::INTEGER as low_users,
        COUNT(CASE WHEN risk_level = 'normal' THEN 1 END)::INTEGER as normal_users,
        AVG(risk_score)::NUMERIC as avg_risk_score
    FROM user_risk_scores 
    WHERE tenant_id = p_tenant_id;
END;
$$ LANGUAGE plpgsql;

-- Activer Row-Level Security pour les tables critiques
ALTER TABLE cases ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE case_notes ENABLE ROW LEVEL SECURITY;

-- Créer des politiques de sécurité qui filtrent les données
-- La politique utilise une variable de session que l'API devra définir à chaque connexion
CREATE POLICY tenant_isolation_policy_cases ON cases
FOR ALL
USING (tenant_id = current_setting('osiris.tenant_id')::integer);

CREATE POLICY tenant_isolation_policy_evidence ON evidence
FOR ALL
USING (tenant_id = current_setting('osiris.tenant_id')::integer);

CREATE POLICY tenant_isolation_policy_case_notes ON case_notes
FOR ALL
USING (tenant_id = current_setting('osiris.tenant_id')::integer);

-- Activer RLS pour la table de logs
ALTER TABLE response_actions_log ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_policy_response_log ON response_actions_log
FOR ALL
USING (tenant_id = current_setting('osiris.tenant_id')::integer);

-- Activer RLS pour les profils
ALTER TABLE user_behavior_profiles ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_policy_user_profiles ON user_behavior_profiles
FOR ALL
USING (tenant_id = current_setting('osiris.tenant_id')::integer);

-- Activer RLS pour les profils hôtes
ALTER TABLE host_behavior_profiles ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_policy_host_profiles ON host_behavior_profiles
FOR ALL
USING (tenant_id = current_setting('osiris.tenant_id')::integer);

-- Activer RLS pour les scores de risque
ALTER TABLE user_risk_scores ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_policy_risk_scores ON user_risk_scores
FOR ALL
USING (tenant_id = current_setting('osiris.tenant_id')::integer);

-- Activer RLS pour les alertes critiques
ALTER TABLE critical_alerts ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_policy_critical_alerts ON critical_alerts
FOR ALL
USING (tenant_id = current_setting('osiris.tenant_id')::integer);

-- Activer RLS pour les playbooks
ALTER TABLE automation_playbooks ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_policy_playbooks ON automation_playbooks
FOR ALL
USING (tenant_id = current_setting('osiris.tenant_id')::integer);

-- Activer RLS pour les indicateurs
ALTER TABLE threat_intel_indicators ENABLE ROW LEVEL SECURITY;

CREATE POLICY tenant_isolation_policy_threat_intel ON threat_intel_indicators
FOR ALL
USING (tenant_id = current_setting('osiris.tenant_id')::integer); 