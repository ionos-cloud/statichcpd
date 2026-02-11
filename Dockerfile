FROM debian:trixie-slim

LABEL maintainer="Reshma Sreekumar <reshma.sreekumar@cloud.ionos.com>"
LABEL description="A Static Host Configuration Protocol Daemon"

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-dpkt \
    python3-pyroute2 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create necessary directories
RUN mkdir -p /etc/statichcpd \
    /usr/share/statichcpd \
    /var/lib/statichcpd

# Copy configuration files
COPY statichcpd.conf /etc/statichcpd/
COPY statichcpd_client_attr_list.csv /etc/statichcpd/
COPY default_attr.csv /usr/share/statichcpd/
COPY default_v6attr.csv /usr/share/statichcpd/

# Copy the application
COPY statichcpd/ /opt/statichcpd/statichcpd/
COPY setup.py /opt/statichcpd/
COPY README.md /opt/statichcpd/
COPY debian/changelog /opt/statichcpd/debian/

# Install the application
WORKDIR /opt/statichcpd
RUN pip3 install --break-system-packages .

# Set environment variable for options (matching debian/statichcpd.default)
ENV OPTIONS="-a /etc/statichcpd/"

# Expose DHCP ports (67/udp for DHCPv4, 547/udp for DHCPv6)
EXPOSE 67/udp
EXPOSE 547/udp

# Run the DHCP server
ENTRYPOINT ["python3", "-m", "statichcpd"]
CMD ["-a", "/etc/statichcpd/"]
