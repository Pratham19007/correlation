FROM python:3.11-slim

WORKDIR /app

# Copy application files
COPY correlation_tool/ /app/correlation_tool/
COPY index.html styles.css app.js /app/
COPY wazuh_config.json /app/
COPY sample_wazuh_logs.json /app/

# Set environment
ENV PYTHONUNBUFFERED=1
ENV PORT=8000

EXPOSE 8000

CMD ["python", "-m", "correlation_tool.server", "8000"]
