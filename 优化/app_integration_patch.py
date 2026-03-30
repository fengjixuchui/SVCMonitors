"""
app_integration_patch.py — Shows how to integrate mem_api into existing SVC Monitor app.py

Add these lines to your existing SVC_PC_View/server/app.py:
"""

# ─── Step 1: Copy mem_api.py to your server directory ───
# cp mem_analyzer/server/mem_api.py SVC_PC_View/server/mem_api.py
# cp mem_analyzer/static/mem_analyzer.html SVC_PC_View/static/mem_analyzer.html

# ─── Step 2: Add to imports section of app.py ───
# from mem_api import mem_bp

# ─── Step 3: After app = Flask(...), add ───
# app.register_blueprint(mem_bp)

# ─── Step 4: Add nav link to existing index.html ───
# In the <nav> section of SVC_PC_View/static/index.html, add:
#   <a href="/mem-analyzer" target="_blank" style="color:#bc8cff">🔬 Memory Analyzer</a>

# ─── That's it! The Memory Analyzer will be available at /mem-analyzer ───

# ═══════════════════════════════════════════════════
# Full example of what the modified app.py top looks like:
# ═══════════════════════════════════════════════════

EXAMPLE_APP_PY_HEADER = """
import os, sys, json, time, csv, io, socket, threading, tempfile
from collections import defaultdict
from flask import Flask, request, jsonify, send_from_directory, Response
from flask_socketio import SocketIO, emit

# ──── Memory Analyzer Integration ────
from mem_api import mem_bp

app = Flask(__name__, static_folder='../static', static_url_path='/static')
app.config['SECRET_KEY'] = 'svc-monitor-secret'
socketio = SocketIO(app, cors_allowed_origins='*', async_mode='threading')

# Register Memory Analyzer Blueprint
app.register_blueprint(mem_bp)

# ... rest of existing app.py ...
"""
