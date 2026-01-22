// src/auth/debugUser.js
import db from "../db/sqlite.js";
import { verifyPassword } from "./password.js";

const email = (process.argv[2] || "").trim().toLowerCase();
const pass = process.argv[3] || "";

if (!email || !pass) {
  console.log('Uso: node src/auth/debugUser.js "email" "senha"');
  process.exit(1);
}

const user = db
  .prepare(`SELECT id, name, email, role, is_active, password_hash FROM users WHERE email = ?`)
  .get(email);

console.log("User no DB:", user);

if (!user) process.exit(0);

const ok = await verifyPassword(pass, user.password_hash);
console.log("Senha confere?", ok);
