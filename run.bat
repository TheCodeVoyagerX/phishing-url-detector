@echo off
echo ============================================================
echo Starting Phishing URL Detector Web Application
echo ============================================================
cd /d "%~dp0"
if exist .venv\Scripts\activate.bat (
    call .venv\Scripts\activate.bat
)
echo Launching Streamlit Dashboard on http://localhost:8501 ...
streamlit run app.py
pause
