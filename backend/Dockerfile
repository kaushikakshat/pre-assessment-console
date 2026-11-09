FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends nmap \
 && apt-get clean && useradd --create-home scanner
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
USER scanner
EXPOSE 8000
