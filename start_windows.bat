@echo off
cd /d "%~dp0"
echo Starting Discord Security Bot website...
echo Open http://127.0.0.1:8000/ in your browser.
py -3 app.py
if errorlevel 1 python app.py
pause
