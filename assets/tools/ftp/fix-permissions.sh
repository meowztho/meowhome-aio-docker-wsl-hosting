#!/usr/bin/env bash
set -euo pipefail
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
exec "$PROJECT_DIR/tools/permissions_hardening.sh" --project "$PROJECT_DIR" --apply
