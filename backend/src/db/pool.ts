import { Pool, PoolClient } from 'pg';

/**
 * Single shared connection pool. In a full Nest app you would expose this as a
 * provider; we keep a module singleton so the lock discipline below is obvious
 * and not obscured by DI wiring.
 */
export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: Number(process.env.PG_POOL_MAX ?? 20),
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
  // Hard ceiling so a pathological query can never pin a connection (and its
  // locks) indefinitely.
  statement_timeout: 10_000,
});

export type Isolation = 'read committed' | 'repeatable read' | 'serializable';

/**
 * Run `fn` inside ONE transaction, commit on success, roll back on throw.
 *
 * INVARIANT (enforced by convention + code review): never perform external
 * network I/O — panel HTTP, ad-network HTTP, anything off-box — inside `fn`.
 * Every row lock taken with `FOR UPDATE` is held until COMMIT, and COMMIT
 * happens the instant `fn` returns. Do the locked DB work, return a plain
 * value, THEN make the external call against that value with locks released.
 */
export async function withTransaction<T>(
  fn: (client: PoolClient) => Promise<T>,
  isolation: Isolation = 'read committed',
): Promise<T> {
  const client = await pool.connect();
  try {
    await client.query(`begin isolation level ${isolation}`);
    const result = await fn(client);
    await client.query('commit');
    return result;
  } catch (err) {
    await client.query('rollback').catch(() => undefined);
    throw err;
  } finally {
    client.release();
  }
}
