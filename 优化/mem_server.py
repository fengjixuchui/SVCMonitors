#!/usr/bin/env python3
"""
mem_server.py — Standalone launcher for Memory Analyzer
Can run independently or be integrated into existing SVC Monitor app.py

Usage:
  # Standalone (port 5001):
  python3 mem_server.py

  # Or integrate into existing app.py:
  #   from mem_api import mem_bp
  #   app.register_blueprint(mem_bp)
"""

import sys
import os

# Add server dir to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'server'))

from flask import Flask
from flask_cors import CORS
from mem_api import mem_bp

app = Flask(__name__,
    static_folder=os.path.join(os.path.dirname(__file__), 'static'),
    static_url_path='/static')

# Enable CORS for all routes (needed if PC Viewer runs on different port)
CORS(app)

# Register memory analysis blueprint
app.register_blueprint(mem_bp)

# Root redirects to analyzer
@app.route("/")
def index():
    return """<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0;url=/mem-analyzer"></head></html>"""

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="SVC Monitor Memory Analyzer Server")
    parser.add_argument("--host", default="0.0.0.0", help="Bind address")
    parser.add_argument("--port", type=int, default=5001, help="Port")
    parser.add_argument("--debug", action="store_true", help="Debug mode")
    args = parser.parse_args()

    print(f"""
╔═══════════════════════════════════════════════════╗
║  SVC Monitor — Memory Analyzer Server             ║
║  http://{args.host}:{args.port}/mem-analyzer      ║
╚═══════════════════════════════════════════════════╝
    """)
    app.run(host=args.host, port=args.port, debug=args.debug)
