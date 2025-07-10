FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY secure_vault2.py .

EXPOSE 5000

CMD ["python", "secure_vault2.py"]