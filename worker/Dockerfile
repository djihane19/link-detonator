# Sandbox worker image. Build with this directory as the context:
#   docker build -t link-detonator-worker worker/
# Files are copied by name so a build from the repo root fails instead of
# pulling the whole repository into the image.
FROM mcr.microsoft.com/playwright/python:v1.64.1-noble

ENV PYTHONDONTWRITEBYTECODE=1

COPY requirements.txt worker.py qr_decode.py /worker/
COPY fixtures/ /worker/fixtures/

RUN python -m pip install --no-cache-dir -r /worker/requirements.txt \
    && python -c "import importlib.metadata as m; assert m.version('playwright') == '1.64.1'" \
    && chmod -R a+rX /worker

USER pwuser
WORKDIR /worker
