FROM python:3.11-slim
RUN groupadd -r paneluser && useradd -r -g paneluser -d /app -s /sbin/nologin paneluser
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py sandbox_runner.py ./
RUN mkdir -p /app/panel_data/users_data /app/panel_data/backups /app/panel_data/temp && chown -R paneluser:paneluser /app
USER paneluser
EXPOSE 5000
ENV PORT=5000
ENV PYTHONUNBUFFERED=1
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 CMD python -c "import urllib.request; urllib.request.urlopen(chr(104)+chr(116)+chr(116)+chr(112)+'://localhost:5000/login')" || exit 1
CMD ["python", "main.py"]
