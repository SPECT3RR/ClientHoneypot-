# Convenience/repeatability isolation for the controller process.
# NOTE: this is NOT a security sandbox against a real browser exploit
# escaping to the host kernel. For actual malicious-URL research, run this
# container inside a disposable VM/cloud sandbox with restricted egress.
FROM mcr.microsoft.com/playwright/python:v1.45.0-jammy

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY decoy_app/ ./decoy_app/
COPY config/ ./config/

ENV PYTHONUNBUFFERED=1
WORKDIR /app/src

ENTRYPOINT ["python", "orchestrator.py"]
