FROM python:3.12-slim
RUN useradd --create-home app && mkdir /data && chown app /data
WORKDIR /app
COPY skillcheck.py server.py ./
USER app
EXPOSE 8080
CMD ["python3", "server.py", "--host", "0.0.0.0", "--port", "8080", "--db", "/data/reports.db"]
