#!/bin/sh
set -eu

: "${AUDIT_CRON:=17 5 * * 6}"
: "${TZ:=UTC}"
: "${AUDIT_REPORTS_DIR:=/reports}"
: "${AUDIT_RUN_ON_START:=0}"

mkdir -p "$AUDIT_REPORTS_DIR"
mkdir -p /var/log

cat > /app/run_audit_once.sh <<EOF
#!/bin/sh
set -eu
export TZ=$(printf '%s' "$TZ")
export AUDIT_REPORTS_DIR=$(printf '%s' "$AUDIT_REPORTS_DIR")
export AUDIT_TARGET_HOST=$(printf '%s' "${AUDIT_TARGET_HOST:-generator}")
export AUDIT_TARGET_TCP_PORT=$(printf '%s' "${AUDIT_TARGET_TCP_PORT:-1420}")
export AUDIT_TARGET_PREMIX_PORT=$(printf '%s' "${AUDIT_TARGET_PREMIX_PORT:-1421}")
export AUDIT_TARGET_HTTP_URL=$(printf '%s' "${AUDIT_TARGET_HTTP_URL:-http://generator:8080}")
export AUDIT_SAMPLE_SIZE=$(printf '%s' "${AUDIT_SAMPLE_SIZE:-20971520}")
export AUDIT_PREMIX_SIZE=$(printf '%s' "${AUDIT_PREMIX_SIZE:-8388608}")
export AUDIT_RNGTEST_BLOCKS=$(printf '%s' "${AUDIT_RNGTEST_BLOCKS:-1000}")
export AUDIT_DIEHARDER_TESTS=$(printf '%s' "${AUDIT_DIEHARDER_TESTS:-0,1,2,8,15,100}")
export AUDIT_SHA512_ROUNDS=$(printf '%s' "${AUDIT_SHA512_ROUNDS:-32}")
export AUDIT_SOCKET_TIMEOUT_SEC=$(printf '%s' "${AUDIT_SOCKET_TIMEOUT_SEC:-5}")
export AUDIT_FETCH_MAX_SEC=$(printf '%s' "${AUDIT_FETCH_MAX_SEC:-300}")
export AUDIT_MAX_TCP_SESSIONS=$(printf '%s' "${AUDIT_MAX_TCP_SESSIONS:-1024}")
export AUDIT_THROUGHPUT_WARN_MIB=$(printf '%s' "${AUDIT_THROUGHPUT_WARN_MIB:-0.5}")
export AUDIT_PRACTRAND=$(printf '%s' "${AUDIT_PRACTRAND:-0}")
export AUDIT_PRACTRAND_TLMAX=$(printf '%s' "${AUDIT_PRACTRAND_TLMAX:-256M}")
export AUDIT_PRACTRAND_MAX_BYTES=$(printf '%s' "${AUDIT_PRACTRAND_MAX_BYTES:-33554432}")
export AUDIT_CHAIN_SECRET=$(printf '%s' "${AUDIT_CHAIN_SECRET:-}")
/usr/bin/python3 /app/run_audit.py >> /var/log/entropy-audit.log 2>&1
EOF
chmod +x /app/run_audit_once.sh

cat > /tmp/root.cron <<EOF
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
TZ=$TZ
$AUDIT_CRON /app/run_audit_once.sh
EOF
chmod 0600 /tmp/root.cron
crontab /tmp/root.cron

if [ "$AUDIT_RUN_ON_START" = "1" ]; then
  /app/run_audit_once.sh || true
fi

touch /var/log/entropy-audit.log
exec cron -f
