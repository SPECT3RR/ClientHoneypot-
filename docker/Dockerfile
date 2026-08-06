# Hunting container: one disposable session's browser.
#
# The security boundary is NOT this container. It is the WSL2 utility VM the
# container runs inside — a real Linux kernel in a lightweight VM. A browser
# exploit lands in the container; a container escape lands in the VM; reaching
# Windows from there needs a hypervisor or virtio-interop exploit, which is a
# different class of attacker than a drive-by kit.
#
# Treat the container as the process/filesystem layer of a layered defence,
# not as the defence itself.
FROM mcr.microsoft.com/playwright/python:v1.45.0-jammy

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/ ./src/
COPY decoy_app/ ./decoy_app/
COPY dashboard/ ./dashboard/
COPY config/ ./config/
# No tests/. .dockerignore excludes them, and the suite documents every
# detection rule and threshold the platform has -- nothing that hunts needs
# it. Secrets (config/intel_keys.json, config/canary_tokens.json) are excluded
# there too; they were being baked in here and shipped into the decoy.

ENV PYTHONUNBUFFERED=1

# Never run the browser as root: an exploit that inherits root inside the
# container makes the escape to the VM materially easier.
RUN useradd -m -u 10001 hunter && chown -R hunter:hunter /app
USER hunter

ENTRYPOINT ["python", "src/v2_orchestrator.py"]
