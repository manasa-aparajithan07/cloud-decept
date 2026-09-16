#!/bin/bash
# CloudDecept Local Development Setup
# Run this on your laptop for local development

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

echo "=========================================="
echo "  CloudDecept Local Development Setup"
echo "=========================================="
echo ""

# Check prerequisites
check_prereqs() {
    log_info "Checking prerequisites..."

    for cmd in docker docker-compose git; do
        if ! command -v $cmd &> /dev/null; then
            log_error "$cmd not found. Please install it first."
            exit 1
        fi
    done

    # Check Docker is running
    if ! docker info &> /dev/null; then
        log_error "Docker daemon not running. Start Docker Desktop/Engine."
        exit 1
    fi

    log_success "Prerequisites OK"
}

# Create directory structure
create_dirs() {
    log_info "Creating directory structure..."

    mkdir -p honeypot_data
    mkdir -p configs/clickhouse
    mkdir -p configs/cowrie
    mkdir -p logs

    log_success "Directories created"
}

# Pull Docker images
pull_images() {
    log_info "Pulling Docker images (this may take a while)..."

    # Pull base images
    docker pull clickhouse/clickhouse-server:24.8
    docker pull postgres:16-alpine
    docker pull redis:7-alpine
    docker pull ollama/ollama:latest
    docker pull node:20-alpine
    docker pull python:3.11-slim

    log_success "Base images pulled"
}

# Start databases (Stage 1)
start_databases() {
    log_info "Starting databases (Stage 1)..."

    docker-compose up -d clickhouse postgres redis

    # Wait for health checks
    log_info "Waiting for databases to be healthy..."
    sleep 10

    # Check ClickHouse
    for i in {1..30}; do
        if curl -s http://localhost:8123/ping | grep -q "Ok"; then
            log_success "ClickHouse ready"
            break
        fi
        sleep 2
    done

    # Check PostgreSQL
    for i in {1..30}; do
        if docker-compose exec -T postgres pg_isready -U deception &> /dev/null; then
            log_success "PostgreSQL ready"
            break
        fi
        sleep 2
    done

    # Check Redis
    for i in {1..10}; do
        if docker-compose exec -T redis redis-cli ping &> /dev/null; then
            log_success "Redis ready"
            break
        fi
        sleep 1
    done
}

# Initialize ClickHouse schema
init_clickhouse() {
    log_info "Initializing ClickHouse schema..."

    docker-compose exec -T clickhouse clickhouse-client --user deception --password deception123 --multiquery << 'EOF'
CREATE DATABASE IF NOT EXISTS deception;

CREATE TABLE IF NOT EXISTS deception.ssh_sessions (
    session_id String,
    start_time DateTime,
    end_time DateTime,
    duration UInt32,
    attacker_ip String,
    attacker_country String,
    attacker_asn String,
    commands_count UInt32,
    primary_intent String,
    intent_confidence Float32,
    skill_level UInt8,
    cloud_provider String,
    org_profile String,
    status String
) ENGINE = MergeTree()
PARTITION BY toDate(start_time)
ORDER BY (start_time, session_id);

CREATE TABLE IF NOT EXISTS deception.ssh_commands (
    session_id String,
    timestamp DateTime,
    command String,
    output String,
    intent String,
    confidence Float32,
    adaptation_applied Bool,
    adaptation_strategy String
) ENGINE = MergeTree()
PARTITION BY toDate(timestamp)
ORDER BY (session_id, timestamp);

CREATE TABLE IF NOT EXISTS deception.cloud_api_calls (
    session_id String,
    timestamp DateTime,
    endpoint String,
    method String,
    request_body String,
    response_body String,
    intent String,
    adapted Bool,
    cloud_provider String
) ENGINE = MergeTree()
PARTITION BY toDate(timestamp)
ORDER BY (session_id, timestamp);

CREATE TABLE IF NOT EXISTS deception.intent_predictions (
    session_id String,
    timestamp DateTime,
    intent String,
    confidence Float32,
    skill_level UInt8,
    reasoning String,
    commands_array Array(String)
) ENGINE = MergeTree()
PARTITION BY toDate(timestamp)
ORDER BY (session_id, timestamp);

CREATE TABLE IF NOT EXISTS deception.adaptations (
    session_id String,
    timestamp DateTime,
    intent String,
    endpoint String,
    original_response String,
    adapted_response String,
    strategy String
) ENGINE = MergeTree()
PARTITION BY toDate(timestamp)
ORDER BY (session_id, timestamp);
EOF

    log_success "ClickHouse schema initialized"
}

# Initialize PostgreSQL schema
init_postgres() {
    log_info "Initializing PostgreSQL schema..."

    docker-compose exec -T postgres psql -U deception -d deception << 'EOF'
CREATE TABLE IF NOT EXISTS threat_intel (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(64),
    created_at TIMESTAMP DEFAULT NOW(),
    ioc_type VARCHAR(32),
    ioc_value TEXT,
    confidence FLOAT,
    context TEXT
);

CREATE TABLE IF NOT EXISTS mitre_techniques (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(64),
    technique_id VARCHAR(16),
    technique_name TEXT,
    tactic VARCHAR(64),
    severity VARCHAR(16),
    trigger VARCHAR(256),
    detected_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS session_summaries (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(64) UNIQUE,
    summary_json JSONB,
    risk_level VARCHAR(16),
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    session_id VARCHAR(64),
    alert_type VARCHAR(64),
    severity VARCHAR(16),
    message TEXT,
    acknowledged BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_threat_intel_session ON threat_intel(session_id);
CREATE INDEX IF NOT EXISTS idx_mitre_session ON mitre_techniques(session_id);
CREATE INDEX IF NOT EXISTS idx_alerts_session ON alerts(session_id);
EOF

    log_success "PostgreSQL schema initialized"
}

# Start backend services (Stage 2)
start_backend_services() {
    log_info "Starting backend services (Stage 2)..."

    docker-compose up -d event-collector llm-gateway backend-api

    log_info "Waiting for backend services..."

    # Event Collector
    for i in {1..60}; do
        if curl -s http://localhost:8000/health 2>/dev/null | grep -q "healthy"; then
            log_success "Event Collector ready"
            break
        fi
        sleep 2
    done

    # LLM Gateway
    for i in {1..60}; do
        if curl -s http://localhost:8003/health 2>/dev/null | grep -q "healthy"; then
            log_success "LLM Gateway ready"
            break
        fi
        sleep 2
    done

    # Backend API
    for i in {1..60}; do
        if curl -s http://localhost:8004/health 2>/dev/null | grep -q "healthy"; then
            log_success "Backend API ready"
            break
        fi
        sleep 2
    done

    # Initialize schemas via backend-api
    log_info "Initializing schemas via Backend API..."
    sleep 5
    for i in {1..10}; do
        if curl -s http://localhost:8004/health 2>/dev/null | grep -q "healthy"; then
            log_success "Backend API confirmed healthy"
            break
        fi
        sleep 2
    done
}

# Start honeypot & API services (Stage 3)
start_honeypot_services() {
    log_info "Starting honeypot & API services (Stage 3)..."

    docker-compose up -d cowrie-ssh cloud-api-mock

    log_info "Waiting for honeypot services..."

    for i in {1..30}; do
        if docker-compose ps cowrie-ssh | grep -q "Up"; then
            log_success "Cowrie SSH ready"
            break
        fi
        sleep 2
    done

    for i in {1..30}; do
        if curl -s http://localhost:8080/health 2>/dev/null | grep -q "healthy"; then
            log_success "Cloud API Mock ready"
            break
        fi
        sleep 2
    done

    # Start AI engines
    log_info "Starting AI engines..."
    docker-compose up -d intent-engine adaptive-engine threat-intel

    for svc in intent-engine adaptive-engine threat-intel; do
        for i in {1..30}; do
            if docker-compose ps "$svc" | grep -q "Up"; then
                log_success "$svc ready"
                break
            fi
            sleep 2
        done
    done
}

# Start dashboard (Stage 4)
start_dashboard() {
    log_info "Starting dashboard (Stage 4)..."

    docker-compose up -d dashboard

    for i in {1..30}; do
        if curl -s http://localhost:3000 2>/dev/null | head -1 | grep -q "html"; then
            log_success "Dashboard ready"
            break
        fi
        sleep 2
    done
}

# Start Ollama and pull model (Stage 5)
setup_ollama() {
    log_info "Starting Ollama and pulling model (Stage 5)..."

    docker-compose up -d ollama

    # Wait for Ollama
    for i in {1..60}; do
        if curl -s http://localhost:11434/api/tags &> /dev/null; then
            log_success "Ollama ready"
            break
        fi
        sleep 5
    done

    # Pull ARM64 optimized model for local dev
    log_info "Pulling Llama 3.2 3B (ARM64 optimized for local dev)..."
    docker-compose exec ollama ollama pull llama3.2:3b

    log_success "Model ready"
}

# Build custom services
build_services() {
    log_info "Building custom services..."

    docker-compose build \
        cloud-api-mock \
        event-collector \
        llm-gateway \
        backend-api \
        intent-engine \
        adaptive-engine \
        threat-intel \
        dashboard

    log_success "Services built"
}

# Main
main() {
    check_prereqs
    create_dirs
    pull_images
    start_databases
    init_clickhouse
    init_postgres
    build_services
    start_backend_services
    start_honeypot_services
    start_dashboard
    setup_ollama
    show_access
}

# Show access info
show_access() {
    echo ""
    echo "=========================================="
    echo "  CloudDecept Local Development Ready!"
    echo "=========================================="
    echo ""
    echo "Access Points:"
    echo "  SSH Honeypot:        ssh -p 2222 ubuntu@localhost"
    echo "  Cloud API Mock:      http://localhost:8080"
    echo "  Dashboard:           http://localhost:3000"
    echo "  Event Collector:     http://localhost:8000/health"
    echo "  Intent Engine:       http://localhost:8001/health"
    echo "  Adaptive Engine:     http://localhost:8002/health"
    echo "  LLM Gateway:         http://localhost:8003/health"
    echo "  Backend API:         http://localhost:8004/health"
    echo "  Ollama API:          http://localhost:11434"
    echo "  ClickHouse HTTP:     http://localhost:8123"
    echo "  PostgreSQL:          localhost:5432"
    echo "  Redis:               localhost:6379"
    echo ""
    echo "Test Commands:"
    echo "  # Test Cloud API"
    echo "  curl http://localhost:8080/aws/ec2/describe-instances"
    echo ""
    echo "  # Test SSH honeypot (in another terminal)"
    echo "  ssh -p 2222 ubuntu@localhost"
    echo "  # password: ubuntu"
    echo ""
    echo "  # View logs"
    echo "  docker-compose logs -f cowrie-ssh"
    echo ""
    echo "Default Credentials (Cowrie):"
    echo "  ubuntu:ubuntu, root:root, admin:admin, user:user"
    echo ""
}

main "$@"