FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    bison \
    flex \
    libssl-dev \
    pkg-config \
    libcurl4-openssl-dev \
    libxml2-dev \
    libpcre2-dev \
    ca-certificates \
    procps \
    net-tools \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/kamailio
COPY . /usr/src/kamailio

RUN make cfg && \
    make -j$(nproc) all modules=modules/smpp modules/sl modules/tm modules/pv modules/maxfwd modules/textops modules/xlog modules/rr modules/siputils modules/kex modules/corex && \
    make install-bin install-modules modules=modules/smpp modules/sl modules/tm modules/pv modules/maxfwd modules/textops modules/xlog modules/rr modules/siputils modules/kex modules/corex install-cfg

EXPOSE 5060/udp 5060/tcp 2779/tcp

CMD ["/usr/local/sbin/kamailio", "-DD", "-E"]
