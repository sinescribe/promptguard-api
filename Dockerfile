FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY promptguard_api /app/promptguard_api
COPY app.py /app/app.py
COPY test_api.py /app/test_api.py

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1

CMD ["uvicorn", "promptguard_api.app:app", "--host", "0.0.0.0", "--port", "8000"]
