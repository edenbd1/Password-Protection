FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY encryption_server.py .

CMD ["python", "encryption_server.py"] 