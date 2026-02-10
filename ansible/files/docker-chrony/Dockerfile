# Chrony NTP Server for SONiC Virtual Testbed
# This container provides NTP time synchronization for DUTs on the management network
FROM alpine:3.19

LABEL maintainer="SONiC Community"
LABEL description="Chrony NTP server for SONiC virtual testbed management network"

# Install chrony, libcap for setcap
RUN apk add --no-cache chrony tzdata libcap

# Create chrony directories and set permissions
# The chrony user/group is created by the chrony package
RUN mkdir -p /var/run/chrony /var/lib/chrony /var/log/chrony && \
    chown -R chrony:chrony /var/run/chrony /var/lib/chrony /var/log/chrony /etc/chrony

# Set file capabilities on chronyd binary to allow binding to port 123 and setting time
# This allows running as non-root while still performing privileged operations
RUN setcap 'cap_net_bind_service,cap_sys_time+ep' /usr/sbin/chronyd

# Copy configuration file
COPY chrony.conf /etc/chrony/chrony.conf
RUN chown chrony:chrony /etc/chrony/chrony.conf

# Expose NTP port (UDP 123)
EXPOSE 123/udp

# Health check - run as chrony user
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD chronyc tracking || exit 1

# Run as non-root user for security
USER chrony

# Run chrony in foreground (no -u flag needed since already running as chrony)
CMD ["chronyd", "-d", "-f", "/etc/chrony/chrony.conf"]
