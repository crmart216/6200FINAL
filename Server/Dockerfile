FROM python:3.12-slim
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY requirements.txt /tmp/server-requirements.txt
RUN python -m pip install --no-cache-dir -r /tmp/server-requirements.txt
COPY Server/ Server/
COPY Security/ Security/
RUN chmod -R a+rX /app/Server /app/Security
USER 10001:10001
EXPOSE 8000
CMD ["python", "-m", "uvicorn", "Server.main:app", "--host", "0.0.0.0", "--port", "8000"]