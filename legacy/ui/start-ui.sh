#!/bin/sh
# Starts the migration UI (127.0.0.1 only). Keep this terminal open; Ctrl+C stops it.
cd "$(dirname "$0")/.." && exec python3 ui/server/migration_ui.py "$@"
