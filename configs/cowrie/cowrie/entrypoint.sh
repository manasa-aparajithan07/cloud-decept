#!/bin/bash
set -e

# Fix ownership of mounted volumes before dropping to cowrie user
# This runs as root (before USER cowrie in Dockerfile)
# Handles both fresh deployments and existing volumes

# Ensure required directories exist
mkdir -p /cowrie/tty /cowrie/dl /cowrie/var/log/cowrie /cowrie/var/lib/cowrie/downloads /cowrie/var/run /cowrie/twistedplugin

# Fix ownership of cowrie_tty volume (mounted at /cowrie/tty)
# Only change if not already owned by cowrie (UID 1000)
if [ "$(stat -c '%u' /cowrie/tty)" != "1000" ]; then
    chown -R 1000:1000 /cowrie/tty
fi

# Fix ownership of cowrie_dl volume (mounted at /cowrie/dl)
if [ "$(stat -c '%u' /cowrie/dl)" != "1000" ]; then
    chown -R 1000:1000 /cowrie/dl
fi

# Fix ownership of cowrie_logs volume (mounted at /cowrie/var/log/cowrie)
if [ "$(stat -c '%u' /cowrie/var/log/cowrie)" != "1000" ]; then
    chown -R 1000:1000 /cowrie/var/log/cowrie
fi

# Ensure SSH host keys are owned by cowrie
chown -R 1000:1000 /cowrie/etc/ssh_host_*_key* 2>/dev/null || true

# Execute cowrie as the cowrie user
exec gosu cowrie "$@"