#!/bin/sh
set -e

# Ensure directories exist and are owned by pentestbot
for dir in /app/data /app/data/work /app/logs /app/reports; do
  mkdir -p "$dir"
done

# Update nuclei templates if the template directory is empty or missing yaml files
NUCLEI_TPL_DIR="/home/pentestbot/.config/nuclei/templates"
if [ ! -d "$NUCLEI_TPL_DIR" ] || [ -z "$(find "$NUCLEI_TPL_DIR" -name '*.yaml' 2>/dev/null | head -1)" ]; then
  echo "[entrypoint] Nuclei templates missing or empty — downloading..."
  gosu pentestbot nuclei -update-templates 2>&1 | tail -5 || echo "[entrypoint] Template update failed."
fi

# Ensure webanalyze has its technologies.json database
if ! gosu pentestbot webanalyze -host http://localhost -silent 2>&1 | grep -q "technologies.json" 2>/dev/null; then
  true  # technologies.json exists
else
  echo "[entrypoint] Downloading webanalyze technologies.json..."
  gosu pentestbot webanalyze -update 2>/dev/null || echo "[entrypoint] webanalyze update skipped."
fi

# Fix ownership of writable application volumes. Avoid recursive chown of
# /home/pentestbot because nuclei templates can contain many files and can
# block startup on small disks after Docker volume/cache cleanup.
chown -R pentestbot:pentestbot /app/data /app/logs /app/reports 2>/dev/null || true
chown pentestbot:pentestbot /home/pentestbot /home/pentestbot/.config /home/pentestbot/.config/nuclei /home/pentestbot/.config/nuclei/templates 2>/dev/null || true

# Allow pentestbot user to modify /etc/hosts for CDN Bypass feature
chmod 666 /etc/hosts 2>/dev/null || true

# Run as pentestbot user
exec gosu pentestbot "$@"
