#!/usr/bin/env bash
# Linux/macOS developer mode: same app, Windows-only sources shown as unavailable.
cd "$(dirname "$0")"; export PYTHONPATH=$PWD/agent/python-agent
python3 -m guardian.main --print-token "$@"
