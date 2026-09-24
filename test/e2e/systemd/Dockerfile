# syntax=docker/dockerfile:1

# Ubuntu-based systemd container for E2E testing (REQ-001).
# Runs systemd as PID 1 so that plexd can be installed and managed
# as a real systemd service, validating the full install-enable-start
# lifecycle.
FROM ubuntu:24.04

# Prevent interactive prompts during package installation.
ENV DEBIAN_FRONTEND=noninteractive

# Install systemd and curl (needed for the install script and health checks),
# and the ssh client plus sshpass the mediated ssh session phase logs in with.
# Clean up apt caches to keep the image small.
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        systemd \
        systemd-sysv \
        curl \
        ca-certificates \
        jq \
        openssh-client \
        sshpass && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# An unprivileged login user: a session as it proves the session helper
# switched uid.
RUN useradd --create-home --shell /bin/bash e2e

# Mask units that cannot run inside a container.
RUN systemctl mask \
    dev-hugepages.mount \
    sys-fs-fuse-connections.mount \
    systemd-logind.service \
    getty.target \
    console-getty.service

# Create directories plexd expects at install time.
RUN mkdir -p /var/lib/plexd /var/run/plexd /etc/plexd && \
    chmod 0700 /var/lib/plexd

# Use tmpfs for cgroup and journal inside the container.
VOLUME ["/sys/fs/cgroup", "/run", "/run/lock", "/tmp"]

STOPSIGNAL SIGRTMIN+3

ENTRYPOINT ["/sbin/init"]
