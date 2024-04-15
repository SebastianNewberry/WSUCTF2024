FROM debian:latest

RUN apt-get update && apt-get install -y software-properties-common gcc

RUN apt-get update && apt-get install -y python3.11 python3-distutils python3-pip python3-apt

WORKDIR /app/

COPY server.py /app/

EXPOSE 8080

CMD ["python3", "server.py", "0.0.0.0", "8080"]