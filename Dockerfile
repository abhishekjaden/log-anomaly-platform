# One image, all services. Each container runs a different entrypoint via compose.
# Bakes in the lap package + trained model so inference loads it at startup.
FROM python:3.12-slim

WORKDIR /app

# system deps kept minimal; torch wheels are self-contained
ENV PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1

# install the package first (deps: numpy, torch) for layer caching
COPY pyproject.toml ./
COPY lap/ ./lap/
# CPU-only torch first (from the CPU index) so `pip install .` doesn't pull the ~5GB CUDA build
RUN pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch \
 && pip install --no-cache-dir . \
&& pip install --no-cache-dir kafka-python>=2.0.2 fastapi>=0.110 "uvicorn[standard]>=0.29" python-multipart>=0.0.9 boto3>=1.34

# app code + model + data dir for the SQLite/results db
COPY services/ ./services/
COPY ml/models/detector.pt ./ml/models/detector.pt
RUN mkdir -p data

# default command is overridden per-service in compose
CMD ["python", "-c", "print('specify a service command')"]