FROM python:3.12-slim

ARG VERSION=1.0.0

LABEL org.opencontainers.image.title="waterguru2mqtt" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.description="WaterGuru → MQTT bridge for Home Assistant/automation" \
      build_version="waterguru2mqtt-${VERSION}"

RUN mkdir /code
WORKDIR /code

COPY requirements.txt .

RUN apt-get update -y && \
    apt-get install -y gcc git && \
    pip install -r requirements.txt

COPY ./waterguru_flask.py .

EXPOSE ${WG_PORT}
CMD [ "python3.12", "/code/waterguru_flask.py" ]
