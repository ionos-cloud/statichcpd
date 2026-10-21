# syntax=docker/dockerfile:1
#
# statichcpd, installed from the .deb that debian-trixie-build produced in
# the same pipeline. docker/ci-image.sh puts the .deb under debs/ in the
# build context; see docker/README.md.

ARG BASE_IMAGE=debian:trixie-slim
FROM ${BASE_IMAGE}

# The package file under debs/, e.g. statichcpd_3.09~deb13_amd64.deb.
ARG DEB_FILE
ARG DEBIAN_FRONTEND=noninteractive

# Its dependencies (python3, python3-dpkt, python3-pyroute2) come from the
# Debian archive; the daemon needs nothing else at runtime. debs/ is
# bind-mounted for this step only, so no layer of the image holds the .deb.
RUN --mount=type=bind,source=debs,target=/tmp/debs \
    : "${DEB_FILE:?pass --build-arg DEB_FILE=<file under debs/>}" \
    && apt-get update \
    && apt-get install -y --no-install-recommends "/tmp/debs/${DEB_FILE}" \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 67/udp 547/udp

# On SIGINT the daemon closes its database and exits (the unit's
# KillSignal=INT). As PID 1 it ignores SIGTERM.
STOPSIGNAL SIGINT

ENTRYPOINT ["python3", "-m", "statichcpd"]
# The unit's OPTIONS, from /etc/default/statichcpd.
CMD ["-a", "/etc/statichcpd/"]
