FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ecc_core ./ecc_core
COPY benchmarks ./benchmarks
COPY sis_app ./sis_app
COPY sis_data ./sis_data
COPY docs ./docs
COPY tests ./tests
COPY cli_demo.py README.md ./

# Allow non-root containers (e.g. Hugging Face Spaces UID 1000) to write SQLite DB
RUN chmod -R 777 /app/sis_data

ENV PORT=7860
EXPOSE 7860

CMD ["sh", "-c", "uvicorn sis_app.main:app --host 0.0.0.0 --port ${PORT:-7860}"]
