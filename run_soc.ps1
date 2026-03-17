Write-Host "🛡️ Starting the SOC Defense System..."
$env:STREAMLIT_EMAIL=""
$env:PYTHONPATH="C:\Users\Maaz\Desktop\cy\ai_ids_soc"

Write-Host "Launching Advanced SOC Dashboard (Frontend GUI)..."
.\venv\Scripts\streamlit.exe run src\app.py
