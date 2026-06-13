#!/bin/sh
# Idempotent migration runner. Applies db/schema.sql then db/migrations/*.sql in
# lexical order, recording each in a schema_migrations table so re-runs are
# no-ops. Each file applies in a SINGLE TRANSACTION (with its bookkeeping insert),
# so a failure rolls back fully and can be safely retried.
#
# Run by the `migrator` compose service; the api waits for it to complete.
set -eu
: "${DATABASE_URL:?DATABASE_URL is required}"

TRACK="psql ${DATABASE_URL} -v ON_ERROR_STOP=1 -X -q -t -A"

# Wait for the tracking table (postgres is already healthy via depends_on).
psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -X -q -c \
  "create table if not exists schema_migrations (filename text primary key, applied_at timestamptz not null default now());"

apply() {
  f="$1"
  name=$(basename "$f")
  if [ "$(${TRACK} -c "select 1 from schema_migrations where filename='${name}'")" = "1" ]; then
    echo "  skip   ${name}"
    return 0
  fi
  echo "  apply  ${name}"
  # -f then -c run in the same session; --single-transaction wraps both, so the
  # file's DDL and the 'recorded' insert commit (or roll back) together.
  psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -X -q --single-transaction \
    -f "$f" \
    -c "insert into schema_migrations(filename) values ('${name}');"
}

apply /db/schema.sql
for m in $(ls /db/migrations/*.sql | sort); do
  apply "$m"
done
echo "migrations complete"
