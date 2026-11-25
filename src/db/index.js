import fs from 'node:fs';
import path from 'node:path';
import pg from 'pg';
import { config } from '../config/env.js';
import { logger } from '../utils/logger.js';

const { Pool } = pg;

// Convert PostgreSQL positional placeholders ($1, $2, ...) to SQLite (?) safely
function convertPgToSqlite(sql, params) {
  const expandedParams = [];
  const convertedSql = sql.replace(/\$(\d+)/g, (_, idxStr) => {
    const idx = Number.parseInt(idxStr, 10) - 1;
    expandedParams.push(params[idx] ?? null);
    return '?';
  });
  return { sql: convertedSql, params: expandedParams };
}

class PostgresAdapter {
  constructor(connectionString) {
    this.dialect = 'postgres';
    const useSsl =
      config.isProduction ||
      connectionString.includes('sslmode=require') ||
      connectionString.includes('ssl=true');

    this.pool = new Pool({
      connectionString,
      max: 10,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: config.dbQueryTimeoutMs,
      statement_timeout: config.dbQueryTimeoutMs,
      query_timeout: config.dbQueryTimeoutMs,
      ssl: useSsl ? { rejectUnauthorized: config.dbSslRejectUnauthorized } : false,
    });

    this.pool.on('error', (err) => {
      logger.error({ err: { message: err.message, code: err.code } }, 'Unexpected PostgreSQL pool error');
    });
  }

  async query(sql, params = []) {
    const result = await this.pool.query(sql, params);
    return { rows: result.rows, rowCount: result.rowCount ?? result.rows.length };
  }

  async exec(sql) {
    await this.pool.query(sql);
  }

  async transaction(fn) {
    const client = await this.pool.connect();
    try {
      await client.query('BEGIN');
      const tx = {
        query: async (sql, params = []) => {
          const r = await client.query(sql, params);
          return { rows: r.rows, rowCount: r.rowCount ?? r.rows.length };
        },
      };
      const result = await fn(tx);
      await client.query('COMMIT');
      return result;
    } catch (err) {
      await client.query('ROLLBACK');
      throw err;
    } finally {
      client.release();
    }
  }

  async ping() {
    await this.query('SELECT 1 AS ok');
    return true;
  }

  async close() {
    await this.pool.end();
  }
}

class SqliteAdapter {
  constructor(sqlitePath) {
    this.dialect = 'sqlite';
    this.sqlitePath = sqlitePath;
    this.db = null;
  }

  async init() {
    const { DatabaseSync } = await import('node:sqlite');
    if (this.sqlitePath !== ':memory:') {
      const dir = path.dirname(this.sqlitePath);
      fs.mkdirSync(dir, { recursive: true });
    }
    this.db = new DatabaseSync(this.sqlitePath);
    this.db.exec('PRAGMA foreign_keys = ON;');
    this.db.exec('PRAGMA journal_mode = WAL;');
    this.db.exec(`PRAGMA busy_timeout = ${config.dbQueryTimeoutMs};`);
  }

  async query(sql, params = []) {
    const { sql: q, params: p } = convertPgToSqlite(sql, params);
    const stmt = this.db.prepare(q);
    const trimmed = q.trim().toUpperCase();
    const returnsRows =
      trimmed.startsWith('SELECT') ||
      trimmed.startsWith('WITH') ||
      trimmed.includes('RETURNING');

    if (returnsRows) {
      const rows = stmt.all(...p);
      return { rows, rowCount: rows.length };
    }
    const info = stmt.run(...p);
    return { rows: [], rowCount: Number(info.changes ?? 0) };
  }

  async exec(sql) {
    this.db.exec(sql);
  }

  async transaction(fn) {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const tx = {
        query: (sql, params = []) => this.query(sql, params),
      };
      const result = await fn(tx);
      this.db.exec('COMMIT');
      return result;
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }
  }

  async ping() {
    this.db.prepare('SELECT 1 AS ok').get();
    return true;
  }

  async close() {
    if (this.db) {
      this.db.close();
      this.db = null;
    }
  }
}

let activeDb = null;

export async function createDatabase(options = {}) {
  const databaseUrl = options.databaseUrl ?? config.databaseUrl;
  const sqlitePath = options.sqlitePath ?? config.sqlitePath;

  if (databaseUrl && (databaseUrl.startsWith('postgres://') || databaseUrl.startsWith('postgresql://'))) {
    const adapter = new PostgresAdapter(databaseUrl);
    return adapter;
  }

  const adapter = new SqliteAdapter(sqlitePath);
  await adapter.init();
  return adapter;
}

export async function getDb() {
  if (!activeDb) {
    activeDb = await createDatabase();
  }
  return activeDb;
}

export function setDb(adapter) {
  activeDb = adapter;
}
