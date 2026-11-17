#!/usr/bin/env bash
# Start the SecReport web interface. Usage: ./start.sh [workspace-folder]
cd "$(dirname "$0")"
exec python3 -m secreport serve --workspace "${1:-workspace}"
