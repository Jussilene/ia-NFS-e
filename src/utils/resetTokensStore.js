import fs from "fs";
import path from "path";

const DB_DIR = path.resolve(process.cwd(), "data");
const DB_FILE = path.join(DB_DIR, "reset_tokens.json");

function ensure() {
  if (!fs.existsSync(DB_DIR)) fs.mkdirSync(DB_DIR, { recursive: true });
  if (!fs.existsSync(DB_FILE)) fs.writeFileSync(DB_FILE, JSON.stringify({ tokens: [] }, null, 2), "utf8");
}

function readDb() {
  ensure();
  return JSON.parse(fs.readFileSync(DB_FILE, "utf8"));
}

function writeDb(db) {
  ensure();
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), "utf8");
}

export async function createResetToken({ userId, email, token, expiresAt }) {
  const db = readDb();
  db.tokens = (db.tokens || []).filter((t) => t.email !== email); // opcional: 1 token por email
  db.tokens.push({ userId, email, token, expiresAt });
  writeDb(db);
}

export async function findResetToken(token) {
  const db = readDb();
  return (db.tokens || []).find((t) => t.token === token) || null;
}

export async function consumeResetToken(token) {
  const db = readDb();
  db.tokens = (db.tokens || []).filter((t) => t.token !== token);
  writeDb(db);
}
