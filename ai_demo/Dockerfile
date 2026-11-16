FROM python:3.13-slim
WORKDIR /app
COPY ai_demo/requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY ai_demo/__init__.py ai_demo/app.py ai_demo/security.py ai_demo/retrieval.py ./ai_demo/
COPY ai_demo/templates ./ai_demo/templates
COPY ai_demo/static ./ai_demo/static
COPY ai_demo/samples ./ai_demo/samples
ENV AI_DEMO_DATA_DIR=/app/data
RUN mkdir -p /app/data && chown -R 1001:0 /app && chmod -R g=u /app
USER 1001
EXPOSE 8081
CMD ["gunicorn", "--bind", "0.0.0.0:8081", "--workers", "1", "--threads", "4", "--timeout", "120", "--access-logfile", "-", "--error-logfile", "-", "ai_demo.app:create_app()"]
