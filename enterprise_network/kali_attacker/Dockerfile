FROM kalilinux/kali-rolling

# Install essential penetration testing tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    curl \
    python3 \
    iputils-ping \
    net-tools \
    dnsutils \
    procps \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/attack

COPY attack.sh .
RUN chmod +x attack.sh

# Keep the container running so we can exec into it
CMD ["tail", "-f", "/dev/null"]
