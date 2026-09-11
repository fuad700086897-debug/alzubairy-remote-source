FROM python:3.13-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .

ENV ALZUBAIRY_DATA_DIR=/data
VOLUME ["/data"]
EXPOSE 8080

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--preload", "--access-logfile", "-", "app:app"]
