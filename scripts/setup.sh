#!/bin/bash
set -euo pipefail

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

log_info "Setting up HoneyTrap..."

if ! command -v python3 &> /dev/null; then
    log_error "Python 3 is required but not installed."
    exit 1
fi

PYTHON_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
log_info "Python version: $PYTHON_VERSION"

if [[ ! -d "venv" ]]; then
    log_info "Creating virtual environment..."
    python3 -m venv venv
fi

log_info "Activating virtual environment..."
source venv/bin/activate

log_info "Upgrading pip..."
pip install --upgrade pip

log_info "Installing dependencies..."
pip install -r requirements.txt

if [[ -f "requirements-dev.txt" ]]; then
    log_info "Installing development dependencies..."
    pip install -r requirements-dev.txt
fi

log_info "Creating directories..."
mkdir -p data/logs
mkdir -p data/uploads/quarantine
mkdir -p data/ssh_keys
mkdir -p data/certs
mkdir -p ml/models

if [[ ! -f ".env" ]]; then
    log_info "Creating .env file from template..."
    cp .env.example .env
    
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
    sed -i "s/change-this-to-a-secure-random-string/$SECRET_KEY/g" .env
    
    log_warn "Please review and update .env with your configuration"
fi

log_info "Generating SSH host key..."
if [[ ! -f "data/ssh_keys/ssh_host_rsa_key" ]]; then
    ssh-keygen -t rsa -b 2048 -f data/ssh_keys/ssh_host_rsa_key -N "" -q
    log_info "SSH host key generated"
fi

log_info "Running database migrations..."
if command -v alembic &> /dev/null; then
    alembic upgrade head || log_warn "Migration failed - database may not be running"
fi

log_info "Running tests..."
pytest tests/ -v --tb=short || log_warn "Some tests failed"

log_info ""
log_info "Setup complete!"
log_info ""
log_info "Next steps:"
log_info "  1. Review and update .env configuration"
log_info "  2. Start PostgreSQL and Redis (or use Docker)"
log_info "  3. Run migrations: alembic upgrade head"
log_info "  4. Start honeypot: python core/honeypot.py"
log_info "  5. Start API: uvicorn api.server:app --reload"
log_info ""
log_info "Or use Docker:"
log_info "  cd docker && docker-compose up -d"
