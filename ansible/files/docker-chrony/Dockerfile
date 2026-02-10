# Chrony NTP Server for SONiC Virtual Testbed
# This container provides NTP time synchronization for DUTs on the management network
FROM alpine:3.19

LABEL maintainer="SONiC Community"
LABEL description="Chrony NTP server for SONiC virtual testbed management network"

# Install chrony
RUN apk add --no-cache chrony tzdata

# Create chrony directories and set permissions
# The chrony user/group is created by the chrony package
RUN mkdir -p /var/run/chrony /var/lib/chrony /var/log/chrony && \
    chown -R chrony:chrony /var/run/chrony /var/lib/chrony /var/log/chrony /etc/chrony

# Copy configuration file
COPY chrony.conf /etc/chrony/chrony.conf
RUN chown chrony:chrony /etc/chrony/chrony.conf

# Expose NTP port (UDP 123)
EXPOSE 123/udp

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD chronyc tracking || exit 1

# Security: chronyd must start as root to bind to port 123 and set system time,
# but it drops privileges to the 'chrony' user immediately after initialization
# using the -u flag. This is the standard secure pattern for NTP daemons.
# nosemgrep: dockerfile.security.missing-user.missing-user

# Run chrony in foreground, dropping privileges to chrony user after init
CMD ["chronyd", "-d", "-u", "chrony", "-f", "/etc/chrony/chrony.conf"]
