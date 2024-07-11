web: python main.py
web: gunicorn --bind :8080 --workers 1 --threads 8 --timeout 0 main:app
web: flask run --host=0.0.0.0
