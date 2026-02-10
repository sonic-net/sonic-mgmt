# Chrony NTP Server for SONiC Virtual Testbed
# This container provides NTP time synchronization for DUTs on the management network
FROM alpine:3.19

LABEL maintainer="SONiC Community"
LABEL description="Chrony NTP server for SONiC virtual testbed management network"

# Install chrony
RUN apk add --no-cache chrony tzdata

# Create chrony directories
RUN mkdir -p /var/run/chrony /var/lib/chrony

# Copy configuration file
COPY chrony.conf /etc/chrony/chrony.conf

# Expose NTP port (UDP 123)
EXPOSE 123/udp

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD chronyc tracking || exit 1

# Run chrony in foreground
CMD ["chronyd", "-d", "-f", "/etc/chrony/chrony.conf"]
