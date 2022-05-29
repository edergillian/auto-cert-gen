FROM python:3.8-slim-buster
WORKDIR /usr/src/app

RUN apt-get update && apt-get -y install \
    libssl-dev

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

ENTRYPOINT [ "python", "./auto_cert_gen_client.py" ]
