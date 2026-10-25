PhishGuard - Phishing URL checker (Flask + SQLite)

Run on your computer
--------------------
1. Open the folder in VS Code or Command Prompt.
2. python -m venv venv
3. venv\Scripts\activate
4. pip install -r requirements.txt
5. python app.py
6. Open http://127.0.0.1:5000 in the browser.

If you start it from VS Code the browser opens by itself.
From Command Prompt it does not. To open it anyway: python app.py browser
To never open it: python app.py nobrowser
If port 5000 is busy: set PORT=5050 and run again.

Login is optional. Guests can check links, but only logged in users get history.

Hosting online (Render)
-----------------------
Build command : pip install -r requirements.txt
Start command : gunicorn app:app
Environment   : SECRET_KEY = some long random text
(Render free plan deletes users.db when it restarts, so accounts can be lost.)
