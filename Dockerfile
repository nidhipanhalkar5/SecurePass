FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    g++ \
    libsqlite3-dev \
    libsodium-dev \
    libasio-dev \
    libboost-all-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/CrowCpp/Crow.git /tmp/crow

WORKDIR /app

COPY backend/server.cpp /app/server.cpp
COPY frontend /app/frontend

RUN g++ -std=c++17 server.cpp -o server \
    -I/tmp/crow/include \
    -lsodium \
    -lsqlite3 \
    -pthread

CMD ["./server"]
