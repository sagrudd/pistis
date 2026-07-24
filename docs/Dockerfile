# syntax=docker/dockerfile:1
FROM docker.io/library/python:3.13.5-slim-bookworm

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

COPY docs/requirements.txt /tmp/pistis-docs-requirements.txt
RUN python -m pip install --no-cache-dir \
    --requirement /tmp/pistis-docs-requirements.txt

WORKDIR /workspace
ENTRYPOINT ["sphinx-build"]
