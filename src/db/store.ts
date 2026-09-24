import Database from 'better-sqlite3';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { ScanResult } from '../types';

const DB_DIR = path.join(os.homedir(), '.agentskillguard');
const DB_PATH = path.join(DB_DIR, 'scans.db');

function getDb(): Database.Database {
  if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
  const db = new Database(DB_PATH);
  db.exec(`
    CREATE TABLE IF NOT EXISTS scans (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      target TEXT NOT NULL,
      tool_name TEXT,
      verdict TEXT NOT NULL,
      verdict_reason TEXT,
      findings_count INTEGER,
      violations_count INTEGER,
      result_json TEXT NOT NULL,
      scanned_at TEXT NOT NULL
    );
  `);
  return db;
}

export function saveScan(result: ScanResult): number {
  const db = getDb();
  try {
    const stmt = db.prepare(`
      INSERT INTO scans (target, tool_name, verdict, verdict_reason, findings_count, violations_count, result_json, scanned_at)
      VALUES (@target, @tool_name, @verdict, @verdict_reason, @findings_count, @violations_count, @result_json, @scanned_at)
    `);
    const info = stmt.run({
      target: result.target,
      tool_name: result.metadata?.name ?? null,
      verdict: result.verdict,
      verdict_reason: result.verdictReason,
      findings_count: result.findings.length,
      violations_count: result.violations.length,
      result_json: JSON.stringify(result),
      scanned_at: result.scannedAt,
    });
    return info.lastInsertRowid as number;
  } finally {
    db.close();
  }
}

export function listScans(limit = 20): any[] {
  const db = getDb();
  try {
    return db
      .prepare(`SELECT id, target, tool_name, verdict, findings_count, violations_count, scanned_at FROM scans ORDER BY id DESC LIMIT ?`)
      .all(limit);
  } finally {
    db.close();
  }
}
