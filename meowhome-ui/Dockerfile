FROM python:3.12-slim
WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

RUN pip install --no-cache-dir \
    fastapi==0.133.0 \
    starlette==1.3.1 \
    uvicorn==0.32.1 \
    jinja2==3.1.6 \
    python-multipart==0.0.31

COPY app /app/app

EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
