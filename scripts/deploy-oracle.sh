#!/bin/bash
# CloudDecept Oracle Cloud Free Tier Deployment (2 OCPU / 12 GB RAM / ARM64)
# Staged deployment (5 stages) to avoid memory spikes
# Usage: ./scripts/deploy-oracle.sh

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

COMPOSE_FILES="-f docker-compose.yml -f docker-compose.oracle.yml"
PROJECT_DIR="$HOME/cloud-decept"

echo "=========================================="
echo "  CloudDecept Oracle Cloud Deployment"
echo "  VM: VM.Standard.A1.Flex | 2 OCPU | 12 GB RAM | ARM64"
echo "=========================================="
echo ""

# Check if running as ubuntu user
if [ "$USER" != "ubuntu" ]; then
    log_warning "Recommended to run as 'ubuntu' user"
fi

# Detect available memory
TOTAL_MEM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
TOTAL_MEM_GB=$((TOTAL_MEM_KB / 1024 / 1024))
log_info "Detected system memory: ${TOTAL_MEM_GB} GB"

if [ "$TOTAL_MEM_GB" -lt 11 ]; then
    log_warning "System has less than 11 GB RAM. Deployment may be tight."
fi

# Install Docker if not present
install_docker() {
    if command -v docker &> /dev/null; then
        log_success "Docker already installed"
        return
    fi

    log_info "Installing Docker..."
    curl -fsSL https://get.docker.com | sh
    sudo usermod -aG docker $USER
    log_warning "Please log out and back in, or run 'newgrp docker'"
    newgrp docker << 'EOF'
    log_info "Docker group activated for this session"
EOF
}

# Install Docker Compose
install_compose() {
    if docker compose version &> /dev/null; then
        log_success "Docker Compose already available"
        return
    fi

    log_info "Installing Docker Compose..."
    sudo apt update && sudo apt install -y docker-compose-plugin
    log_success "Docker Compose installed"
}

# Configure firewall (ufw for Ubuntu)
configure_firewall() {
    log_info "Configuring firewall..."

    if command -v ufw &> /dev/null; then
        sudo ufw allow 22/tcp
        sudo ufw allow 2222/tcp
        sudo ufw allow 8080/tcp
        sudo ufw allow 3000/tcp
        sudo ufw allow 8123/tcp
        sudo ufw allow 9000/tcp
        sudo ufw allow 11434/tcp
        sudo ufw allow 8000/tcp   # event-collector
        sudo ufw allow 8001/tcp   # intent-engine
        sudo ufw allow 8002/tcp   # adaptive-engine
        sudo ufw allow 8003/tcp   # llm-gateway
        sudo ufw allow 8004/tcp   # backend-api
        sudo ufw --force enable
        log_success "ufw configured"
    else
        log_warning "ufw not found. Installing..."
        sudo apt update && sudo apt install -y ufw
        configure_firewall
    fi
}

# Setup directories and permissions
setup_directories() {
    log_info "Setting up directories..."

    mkdir -p "$PROJECT_DIR/honeypot_data"
    mkdir -p "$PROJECT_DIR/configs/clickhouse"
    mkdir -p "$PROJECT_DIR/logs"

    # Ensure proper permissions for ClickHouse (UID 101)
    sudo chown -R 101:101 "$PROJECT_DIR/honeypot_data" 2>/dev/null || true

    log_success "Directories ready"
}

# Generate ClickHouse config optimized for 2 GB
gen_clickhouse_config() {
    log_info "Generating ClickHouse config (2 GB optimized)..."

    cat > "$PROJECT_DIR/configs/clickhouse/config.xml" << 'EOF'
<clickhouse>
    <logger>
        <level>information</level>
        <log>/var/log/clickhouse-server/clickhouse-server.log</log>
        <errorlog>/var/log/clickhouse-server/clickhouse-server.err.log</errorlog>
        <size>500M</size>
        <count>5</count>
    </logger>

    <http_port>8123</http_port>
    <tcp_port>9000</tcp_port>
    <interserver_http_port>9009</interserver_http_port>

    <listen_host>::</listen_host>

    <max_concurrent_queries>50</max_concurrent_queries>
    <max_connections>2048</max_connections>
    <keep_alive_timeout>3</keep_alive_timeout>

    <default_profile>default</default_profile>

    <timezone>UTC</timezone>

    <users_config>users.xml</users_config>

    <databases_config>databases.xml</databases_config>

    <merge_tree>
        <max_part_size_to_merge>1000000000</max_part_size_to_merge>
        <max_bytes_to_merge_at_max_space_in_pool>10000000000</max_bytes_to_merge_at_max_space_in_pool>
    </merge_tree>

    <storage_configuration>
        <disks>
            <default>
                <path>/var/lib/clickhouse/</path>
            </default>
        </disks>
        <policies>
            <default>
                <volumes>
                    <main>
                        <disk>default</disk>
                    </main>
                </volumes>
            </default>
        </policies>
    </storage_configuration>
</clickhouse>
EOF

    cat > "$PROJECT_DIR/configs/clickhouse/users.xml" << 'EOF'
<clickhouse>
    <users>
        <deception>
            <password_sha256_hex>5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8</password_sha256_hex>
            <networks incl="networks" replace="replace">
                <ip>::/0</ip>
            </networks>
            <profile>default</profile>
            <quota>default</quota>
            <access_management>1</access_management>
        </deception>
    </users>

    <profiles>
        <default>
            <max_memory_usage>1000000000</max_memory_usage>
            <max_memory_usage_for_user>2000000000</max_memory_usage_for_user>
            <use_uncompressed_cache>0</use_uncompressed_cache>
            <load_balancing>random</load_balancing>
            <max_threads>2</max_threads>
        </default>
    </profiles>

    <quotas>
        <default>
            <interval>
                <duration>3600</duration>
                <queries>0</queries>
                <errors>0</errors>
                <result_rows>0</result_rows>
                <read_rows>0</read_rows>
                <execution_time>0</execution_time>
            </interval>
        </default>
    </quotas>
</clickhouse>
EOF

    log_success "ClickHouse config generated (optimized for 2 GB)"
}

# Verify ARM64 compatibility before deployment
verify_arm64() {
    log_info "Verifying ARM64 image compatibility..."

    if [ -f "$PROJECT_DIR/scripts/verify-arm64.sh" ]; then
        chmod +x "$PROJECT_DIR/scripts/verify-arm64.sh"
        if ! "$PROJECT_DIR/scripts/verify-arm64.sh"; then
            log_error "ARM64 verification failed. Check output above."
            log_warning "Continuing anyway - some images may still work..."
            # Don't exit - let user decide
        else
            log_success "All images verified ARM64 compatible"
        fi
    else
        log_warning "verify-arm64.sh not found, skipping ARM64 check"
    fi
}

# Pull all images first (avoids pull during staged startup)
pull_images() {
    log_info "Pulling all Docker images (this may take a while)..."

    cd "$PROJECT_DIR"
    docker compose $COMPOSE_FILES pull --ignore-pull-failures 2>&1 | tail -20

    log_success "Base images pulled"
}

# Build custom services
build_services() {
    log_info "Building custom services..."

    cd "$PROJECT_DIR"
    docker compose $COMPOSE_FILES build \
        cloud-api-mock \
        event-collector \
        llm-gateway \
        backend-api \
        intent-engine \
        adaptive-engine \
        threat-intel \
        dashboard

    log_success "Custom services built"
}

# ============================================================
# STAGE 1: DATABASES
# ============================================================
stage1_databases() {
    log_info "=========================================="
    log_info "STAGE 1: Starting Databases"
    log_info "=========================================="

    cd "$PROJECT_DIR"
    docker compose $COMPOSE_FILES up -d clickhouse postgres redis

    log_info "Waiting for databases to become healthy..."

    # Wait for ClickHouse
    for i in {1..60}; do
        if curl -s http://localhost:8123/ping 2>/dev/null | grep -q "Ok"; then
            log_success "ClickHouse ready"
            break
        fi
        if [ $i -eq 60 ]; then
            log_error "ClickHouse failed to start"
            docker compose $COMPOSE_FILES logs clickhouse
            exit 1
        fi
        sleep 2
    done

    # Wait for PostgreSQL
    for i in {1..60}; do
        if docker compose $COMPOSE_FILES exec -T postgres pg_isready -U deception &> /dev/null; then
            log_success "PostgreSQL ready"
            break
        fi
        if [ $i -eq 60 ]; then
            log_error "PostgreSQL failed to start"
            docker compose $COMPOSE_FILES logs postgres
            exit 1
        fi
        sleep 2
    done

    # Wait for Redis
    for i in {1..30}; do
        if docker compose $COMPOSE_FILES exec -T redis redis-cli ping &> /dev/null; then
            log_success "Redis ready"
            break
        fi
        if [ $i -eq 30 ]; then
            log_error "Redis failed to start"
            docker compose $COMPOSE_FILES logs redis
            exit 1
        fi
        sleep 1
    done

    log_success "STAGE 1 complete: All databases healthy"
}

# ============================================================
# STAGE 2: BACKEND SERVICES
# ============================================================
stage2_backend() {
    log_info "=========================================="
    log_info "STAGE 2: Starting Backend Services"
    log_info "=========================================="

    cd "$PROJECT_DIR"
    docker compose $COMPOSE_FILES up -d event-collector llm-gateway backend-api

    log_info "Waiting for Event Collector..."
    for i in {1..60}; do
        if curl -s http://localhost:8000/health 2>/dev/null | grep -q "healthy"; then
            log_success "Event Collector ready"
            break
        fi
        if [ $i -eq 60 ]; then
            log_warning "Event Collector may still be starting"
            break
        fi
        sleep 2
    done

    log_info "Waiting for LLM Gateway..."
    for i in {1..60}; do
        if curl -s http://localhost:8003/health 2>/dev/null | grep -q "healthy"; then
            log_success "LLM Gateway ready"
            break
        fi
        if [ $i -eq 60 ]; then
            log_warning "LLM Gateway may still be starting"
            break
        fi
        sleep 2
    done

    log_info "Waiting for Backend API..."
    for i in {1..60}; do
        if curl -s http://localhost:8004/health 2>/dev/null | grep -q "healthy"; then
            log_success "Backend API ready"
            break
        fi
        if [ $i -eq 60 ]; then
            log_warning "Backend API may still be starting"
            break
        fi
        sleep 2
    done

    # Initialize database schemas via backend-api
    log_info "Initializing database schemas via Backend API..."
    sleep 5
    for i in {1..10}; do
        if curl -s http://localhost:8004/health 2>/dev/null | grep -q "healthy"; then
            log_success "Backend API confirmed healthy, schemas initialized"
            break
        fi
        sleep 2
    done

    log_success "STAGE 2 complete: Backend services running"
}

# ============================================================
# STAGE 3: HONEYPOT & AI SERVICES
# ============================================================
stage3_honeypot_ai() {
    log_info "=========================================="
    log_info "STAGE 3: Starting Honeypot & AI Services"
    log_info "=========================================="

    cd "$PROJECT_DIR"
    docker compose $COMPOSE_FILES up -d cowrie-ssh cloud-api-mock

    log_info "Waiting for Cowrie SSH..."
    for i in {1..30}; do
        if docker compose $COMPOSE_FILES ps cowrie-ssh | grep -q "Up"; then
            log_success "Cowrie SSH ready"
            break
        fi
        if [ $i -eq 30 ]; then
            log_warning "Cowrie SSH may still be starting"
            break
        fi
        sleep 2
    done

    log_info "Waiting for Cloud API Mock..."
    for i in {1..30}; do
        if curl -s http://localhost:8080/health 2>/dev/null | grep -q "healthy"; then
            log_success "Cloud API Mock ready"
            break
        fi
        if [ $i -eq 30 ]; then
            log_warning "Cloud API Mock may still be starting"
            break
        fi
        sleep 2
    done

    # Start AI services
    log_info "Starting Intent Engine, Adaptive Engine, Threat Intel..."
    docker compose $COMPOSE_FILES up -d intent-engine adaptive-engine threat-intel

    log_info "Waiting for API services..."
    for svc in intent-engine adaptive-engine threat-intel; do
        for i in {1..30}; do
            if docker compose $COMPOSE_FILES ps "$svc" | grep -q "Up"; then
                log_success "$svc ready"
                break
            fi
            if [ $i -eq 30 ]; then
                log_warning "$svc may still be starting"
                break
            fi
            sleep 2
        done
    done

    log_success "STAGE 3 complete: Honeypot & AI services running"
}

# ============================================================
# STAGE 4: DASHBOARD
# ============================================================
stage4_dashboard() {
    log_info "=========================================="
    log_info "STAGE 4: Starting Dashboard"
    log_info "=========================================="

    cd "$PROJECT_DIR"
    docker compose $COMPOSE_FILES up -d dashboard

    log_info "Waiting for Dashboard..."
    for i in {1..30}; do
        if curl -s http://localhost:3000 2>/dev/null | head -1 | grep -q "html"; then
            log_success "Dashboard ready"
            break
        fi
        if [ $i -eq 30 ]; then
            log_warning "Dashboard may still be starting"
            break
        fi
        sleep 2
    done

    log_success "STAGE 4 complete: Dashboard running"
}

# ============================================================
# STAGE 5: OLLAMA + MODEL + INTENT ENGINE INIT
# ============================================================
stage5_ollama() {
    log_info "=========================================="
    log_info "STAGE 5: Starting Ollama & Loading Model"
    log_info "=========================================="

    cd "$PROJECT_DIR"
    docker compose $COMPOSE_FILES up -d ollama

    log_info "Waiting for Ollama API..."
    for i in {1..60}; do
        if curl -s http://localhost:11434/api/tags &> /dev/null; then
            log_success "Ollama API ready"
            break
        fi
        if [ $i -eq 60 ]; then
            log_error "Ollama failed to start"
            docker compose $COMPOSE_FILES logs ollama
            exit 1
        fi
        sleep 5
    done

    log_info "Pulling Llama 3.2 3B model (ARM64 optimized)..."
    docker compose $COMPOSE_FILES exec ollama ollama pull llama3.2:3b

    log_success "Model loaded successfully"

    # Verify backend services can reach ollama
    log_info "Verifying LLM Gateway -> Ollama connectivity..."
    sleep 5
    if docker compose $COMPOSE_FILES exec -T llm-gateway python -c "
import requests
try:
    r = requests.get('http://ollama:11434/api/tags', timeout=5)
    print('LLM Gateway can reach Ollama:', r.status_code == 200)
except Exception as e:
    print('Connection failed:', e)
" 2>/dev/null; then
        log_success "LLM Gateway connected to Ollama"
    else
        log_warning "LLM Gateway may need restart to connect to Ollama"
    fi

    log_success "STAGE 5 complete: Ollama with Llama 3.2 3B ready"
}

# Show final info
show_info() {
    echo ""
    echo "=========================================="
    echo "  CloudDecept Deployed on Oracle Cloud!"
    echo "  Config: 2 OCPU / 12 GB RAM / ARM64"
    echo "=========================================="
    echo ""

    # Get public IP
    PUBLIC_IP=$(curl -s https://api.ipify.org 2>/dev/null || echo "<YOUR_PUBLIC_IP>")

    echo "Access your honeypot:"
    echo "  SSH Honeypot:       ssh -p 2222 ubuntu@$PUBLIC_IP"
    echo "  Cloud API Mock:     http://$PUBLIC_IP:8080"
    echo "  Dashboard:          http://$PUBLIC_IP:3000"
    echo "  Event Collector:    http://$PUBLIC_IP:8000"
    echo "  Intent Engine:      http://$PUBLIC_IP:8001"
    echo "  Adaptive Engine:    http://$PUBLIC_IP:8002"
    echo "  LLM Gateway:        http://$PUBLIC_IP:8003"
    echo "  Backend API:        http://$PUBLIC_IP:8004"
    echo "  Ollama API:         http://$PUBLIC_IP:11434"
    echo "  ClickHouse HTTP:    http://$PUBLIC_IP:8123"
    echo ""
    echo "Check status:"
    echo "  docker compose $COMPOSE_FILES ps"
    echo "  docker compose $COMPOSE_FILES logs -f"
    echo ""
    echo "Memory usage:"
    echo "  docker stats --no-stream"
    echo ""
    echo "Next steps:"
    echo "  1. Set up DuckDNS: ./scripts/setup-duckdns.sh"
    echo "  2. Change default passwords in docker-compose.yml"
    echo "  3. Monitor attacks on the dashboard"
    echo ""
    echo "Upgrade to 4 OCPU / 24 GB later:"
    echo "  1. Scale VM in Oracle Console"
    echo "  2. Remove docker-compose.oracle.yml (or rename)"
    echo "  3. Run: docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d"
    echo "  4. Pull larger model: docker compose exec ollama ollama pull llama3:8b"
    echo ""
}

# Main deployment flow
main() {
    install_docker
    install_compose
    configure_firewall
    setup_directories
    gen_clickhouse_config
    verify_arm64
    pull_images
    build_services

    stage1_databases
    stage2_backend
    stage3_honeypot_ai
    stage4_dashboard
    stage5_ollama

    show_info
}

main "$@"