FROM python:3.12-slim

RUN mkdir /code
WORKDIR /code

COPY requirements.txt .

RUN apt-get update -y && \
    apt-get install -y gcc git && \
    pip install -r requirements.txt

# TZ is now controlled at runtime via environment variable
# So leave timezone setup for container start, not image build.

COPY ./waterguru_flask.py .

EXPOSE ${WG_PORT}

CMD [ "python3.12", "/code/waterguru_flask.py" ]