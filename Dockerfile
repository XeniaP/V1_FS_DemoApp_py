FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# OpenShift best practice: UID 1001, GID 0 with group-writable permissions
# OpenShift runs containers with arbitrary UIDs but always GID 0
RUN mkdir -p uploads && \
    chown -R 1001:0 /app && \
    chmod -R g=u /app

USER 1001

EXPOSE 8080

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--timeout", "120", \
     "--access-logfile", "-", "--error-logfile", "-", "app:app"]
