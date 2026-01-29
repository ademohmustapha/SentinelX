#!/bin/bash

PROJECT_DIR="/home/ademoh/Kryphorix"
VENV_DIR="$PROJECT_DIR/venv"

if [ ! -d "$VENV_DIR" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv "$VENV_DIR"
fi

echo "[*] Ensuring pip works..."
"$VENV_DIR/bin/python" -m ensurepip --upgrade

echo "[*] Installing dependencies..."
"$VENV_DIR/bin/python" -m pip install --upgrade pip --break-system-packages
"$VENV_DIR/bin/python" -m pip install requests reportlab rich --break-system-packages

echo "[*] Launching Kryphorix..."
exec "$VENV_DIR/bin/python" "$PROJECT_DIR/main.py"

