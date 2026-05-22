FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend/ ./backend/
COPY frontend/ ./frontend/
COPY data/ ./data/

WORKDIR /app/backend
EXPOSE 8008

CMD ["python", "main.py"]
