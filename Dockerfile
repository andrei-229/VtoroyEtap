FROM python:3.12.1-alpine3.19

WORKDIR /app

COPY requirements.txt requirements.txt
RUN pip3 install -r requirements.txt
RUN pip3 install flask[async]

COPY . .

ENV SERVER_PORT=$SERVER_PORT

CMD ["sh", "-c", "exec python3 -m flask run --host=0.0.0.0 --port=$SERVER_PORT"]