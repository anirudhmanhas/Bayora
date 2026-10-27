FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN groupadd -g 10001 appgroup && \
    useradd -u 10001 -g appgroup -s /bin/bash -m appuser

COPY . .

RUN chown -R appuser:appgroup /app

USER 10001:10001

EXPOSE 3128

CMD ["python", "main.py"]
