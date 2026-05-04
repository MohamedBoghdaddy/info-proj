@echo off
echo Starting AI Cyber Defense Lab Backend...
cd /d "%~dp0backend"
python -m uvicorn main:app --reload --port 8000
