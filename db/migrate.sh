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
  
  # ALTER TYPE ... ADD VALUE cannot run inside a transaction block in PostgreSQL.
  # If the file contains this statement, we run it and record the migration outside a transaction.
  if grep -qi -E "alter type.*add value" "$f"; then
    psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -X -q -f "$f"
    psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -X -q -c "insert into schema_migrations(filename) values ('${name}');"
  else
    psql "${DATABASE_URL}" -v ON_ERROR_STOP=1 -X -q --single-transaction \
      -f "$f" \
      -c "insert into schema_migrations(filename) values ('${name}');"
  fi
}

apply /db/schema.sql
for m in $(ls /db/migrations/*.sql | sort); do
  apply "$m"
done
echo "migrations complete"
