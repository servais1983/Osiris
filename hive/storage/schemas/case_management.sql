-- Table pour les cas d'investigation
CREATE TABLE cases (
    id SERIAL PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    status VARCHAR(50) DEFAULT 'Open', -- Ex: Open, In Progress, Closed
    priority VARCHAR(50) DEFAULT 'Medium', -- Ex: Low, Medium, High, Critical
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Table pour les preuves liées à un cas
CREATE TABLE evidence (
    id SERIAL PRIMARY KEY,
    case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
    summary TEXT NOT NULL,
    source_type VARCHAR(100), -- Ex: 'sigma_alert', 'timeline_event', 'file'
    source_data JSONB, -- Les données brutes de l'événement ou de l'alerte
    added_by VARCHAR(100), -- L'utilisateur qui a ajouté la preuve
    added_at TIMESTAMPTZ DEFAULT NOW()
);

-- Table pour les notes de cas
CREATE TABLE case_notes (
    id SERIAL PRIMARY KEY,
    case_id INTEGER REFERENCES cases(id) ON DELETE CASCADE,
    note TEXT NOT NULL,
    author VARCHAR(100),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Index pour améliorer les performances
CREATE INDEX idx_cases_status ON cases(status);
CREATE INDEX idx_cases_priority ON cases(priority);
CREATE INDEX idx_evidence_case_id ON evidence(case_id);
CREATE INDEX idx_evidence_source_type ON evidence(source_type);
CREATE INDEX idx_case_notes_case_id ON case_notes(case_id); 