#!/bin/bash
# ARM64 Image Compatibility Verification for CloudDecept
# Run before deployment on Oracle Ampere ARM VM

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[FAIL]${NC} $1"; }

# Images used in docker-compose.yml (base) + docker-compose.oracle.yml
# Format: "service:image:tag"
IMAGES=(
    "clickhouse:clickhouse/clickhouse-server:24.8"
    "postgres:postgres:16-alpine"
    "redis:redis:7-alpine"
    "ollama:ollama/ollama:latest"
    "cowrie-ssh:local build (configs/cowrie/cowrie)"
    "cloud-api-mock:local build (cloud-api-mock)"
    "intent-engine:local build (intent-engine)"
    "adaptive-engine:local build (adaptive-engine)"
    "threat-intel:local build (threat-intel)"
    "dashboard:local build (dashboard)"
)

# Multi-arch capable base images (known good for ARM64)
ARM64_IMAGES=(
    "clickhouse/clickhouse-server:24.8"
    "postgres:16-alpine"
    "redis:7-alpine"
    "ollama/ollama:latest"
    "node:20-alpine"
    "python:3.11-slim"
)

check_registry_manifest() {
    local image=$1
    log_info "Checking $image for ARM64 support..."

    # Use docker manifest inspect (requires experimental CLI or buildx)
    if docker manifest inspect "$image" >/dev/null 2>&1; then
        # Check for linux/arm64 in manifest
        local archs=$(docker manifest inspect "$image" 2>/dev/null | jq -r '.[].platform.architecture' 2>/dev/null | sort -u | tr '\n' ' ')
        if echo "$archs" | grep -q "arm64"; then
            log_success "$image supports linux/arm64 (archs: $archs)"
            return 0
        else
            log_warning "$image manifest found but NO arm64 (archs: $archs)"
            return 1
        fi
    else
        log_warning "$image - manifest inspect failed (may not exist or need login)"
        return 1
    fi
}

check_with_buildx() {
    local image=$1
    log_info "Checking $image with buildx..."

    if docker buildx imagetools inspect "$image" >/dev/null 2>&1; then
        local archs=$(docker buildx imagetools inspect "$image" 2>/dev/null | grep -E "linux/(arm64|amd64)" | awk '{print $2}' | sort -u | tr '\n' ' ')
        if echo "$archs" | grep -q "arm64"; then
            log_success "$image supports linux/arm64 (archs: $archs)"
            return 0
        else
            log_warning "$image - NO arm64 variant (archs: $archs)"
            return 1
        fi
    else
        log_warning "$image - buildx inspect failed"
        return 1
    fi
}

pull_and_check_arch() {
    local image=$1
    log_info "Pulling $image to check architecture..."

    if docker pull --platform linux/arm64 "$image" >/dev/null 2>&1; then
        local arch=$(docker inspect --format='{{.Architecture}}' "$image" 2>/dev/null)
        if [[ "$arch" == "arm64" ]]; then
            log_success "$image pulls as ARM64"
            return 0
        else
            log_warning "$image pulled but architecture is $arch (not arm64)"
            return 1
        fi
    else
        log_warning "$image - failed to pull ARM64 variant"
        return 1
    fi
}

check_local_build() {
    local service=$1
    local dockerfile=$2
    local context=$3

    log_info "Checking local build: $service (Dockerfile: $dockerfile)"

    if [[ -f "$context/$dockerfile" ]]; then
        # Check FROM line in Dockerfile
        local base_image=$(grep -i "^FROM" "$context/$dockerfile" | head -1 | awk '{print $2}')
        log_info "  Base image: $base_image"

        # Verify base image supports ARM64
        if check_with_buildx "$base_image"; then
            log_success "$service: base image OK for ARM64"
            return 0
        else
            log_warning "$service: base image $base_image may not support ARM64"
            return 1
        fi
    else
        log_error "$service: Dockerfile not found at $context/$dockerfile"
        return 1
    fi
}

main() {
    echo "=========================================="
    echo "  CloudDecept ARM64 Compatibility Check"
    echo "  Target: Oracle Ampere ARM (linux/arm64)"
    echo "=========================================="
    echo ""

    local failed=0
    local passed=0
    local warnings=0

    # Check base images from Docker Hub
    log_info "=== Checking Base Images (Docker Hub) ==="
    for img in "${ARM64_IMAGES[@]}"; do
        if check_with_buildx "$img"; then
            ((passed++))
        else
            ((warnings++))
        fi
    done

    # Check local builds
    log_info ""
    log_info "=== Checking Local Service Builds ==="

    check_local_build "cloud-api-mock" "Dockerfile" "services/cloud-api-mock" && ((passed++)) || ((failed++))
    check_local_build "intent-engine" "Dockerfile" "services/intent-engine" && ((passed++)) || ((failed++))
    check_local_build "adaptive-engine" "Dockerfile" "services/adaptive-engine" && ((passed++)) || ((failed++))
    check_local_build "threat-intel" "Dockerfile" "services/threat-intel" && ((passed++)) || ((failed++))
    check_local_build "dashboard" "Dockerfile" "apps/dashboard" && ((passed++)) || ((failed++))
    check_local_build "cowrie-ssh" "Dockerfile" "configs/cowrie/cowrie" && ((passed++)) || ((failed++))
    check_local_build "event-collector" "Dockerfile" "backend/collector" && ((passed++)) || ((failed++))
    check_local_build "backend-api" "Dockerfile" "backend/api" && ((passed++)) || ((failed++))
    check_local_build "llm-gateway" "Dockerfile" "backend/gateway" && ((passed++)) || ((failed++))

    # Summary
    echo ""
    echo "=========================================="
    echo "  ARM64 Compatibility Summary"
    echo "=========================================="
    echo -e "${GREEN}Passed: $passed${NC}"
    echo -e "${YELLOW}Warnings: $warnings${NC}"
    echo -e "${RED}Failed: $failed${NC}"
    echo ""

    if [[ $failed -gt 0 ]]; then
        log_error "Some services may not run on ARM64. Review warnings above."
        echo ""
        echo "Common ARM64 alternatives:"
        echo "  - Use node:20-alpine (multi-arch) instead of node:20"
        echo "  - Use python:3.11-slim (multi-arch) instead of python:3.11"
        echo "  - Use golang:1.21-alpine for Go services"
        echo "  - All CloudDecept base images are ARM64 compatible"
        exit 1
    elif [[ $warnings -gt 0 ]]; then
        log_warning "Some base images couldn't be verified (may need login). Proceed with caution."
        exit 0
    else
        log_success "All images verified compatible with linux/arm64!"
        exit 0
    fi
}

# Check prerequisites
if ! command -v docker &>/dev/null; then
    log_error "Docker not found"
    exit 1
fi

if ! command -v jq &>/dev/null; then
    log_info "Installing jq for JSON parsing..."
    sudo apt update && sudo apt install -y jq >/dev/null 2>&1 || true
fi

# Enable buildx if not available
if ! docker buildx version &>/dev/null; then
    log_info "Enabling Docker buildx..."
    docker buildx create --use --name arm64-checker >/dev/null 2>&1 || true
fi

main "$@"