// src/admin/admin.routes.js
import express from "express";
import db from "../db/sqlite.js";
import { requireAuth, requireAdmin } from "../auth/auth.middleware.js";
import { hashPassword } from "../auth/password.js";

const router = express.Router();

// tudo aqui exige estar logado + ser ADMIN
router.use(requireAuth, requireAdmin);

// GET /admin/users
router.get("/users", (_req, res) => {
  const users = db.prepare(`
    SELECT id, name, email, role, is_active, last_login_at, created_at
    FROM users
    ORDER BY created_at DESC
  `).all();

  const totals = db.prepare(`
    SELECT
      SUM(CASE WHEN is_active = 1 THEN 1 ELSE 0 END) AS active,
      SUM(CASE WHEN is_active = 0 THEN 1 ELSE 0 END) AS inactive,
      COUNT(*) AS total
    FROM users
  `).get();

  return res.json({ ok: true, users, totals });
});

// POST /admin/users  (criar usuário)
router.post("/users", async (req, res) => {
  const { name, email, password, role } = req.body || {};

  const n = String(name || "").trim();
  const e = String(email || "").trim().toLowerCase();
  const p = String(password || "");
  const r = String(role || "USER").toUpperCase();

  if (!n || !e || !p) {
    return res.status(400).json({ ok: false, error: "Nome, email e senha são obrigatórios" });
  }

  if (p.length < 6) {
    return res.status(400).json({ ok: false, error: "Senha muito curta (mín. 6)" });
  }

  if (!["USER", "ADMIN"].includes(r)) {
    return res.status(400).json({ ok: false, error: "Role inválida" });
  }

  const exists = db.prepare(`SELECT id FROM users WHERE email = ?`).get(e);
  if (exists) {
    return res.status(409).json({ ok: false, error: "Já existe usuário com esse email" });
  }

  const passHash = await hashPassword(p);

  const info = db.prepare(`
    INSERT INTO users (name, email, password_hash, role, is_active, created_at)
    VALUES (?, ?, ?, ?, 1, ?)
  `).run(n, e, passHash, r, new Date().toISOString());

  return res.status(201).json({ ok: true, id: info.lastInsertRowid });
});

// POST /admin/users/:id/toggle  (ativar/desativar)
router.post("/users/:id/toggle", (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isFinite(id)) return res.status(400).json({ ok: false, error: "ID inválido" });

  const u = db.prepare(`SELECT id, is_active FROM users WHERE id = ?`).get(id);
  if (!u) return res.status(404).json({ ok: false, error: "Usuário não encontrado" });

  const next = u.is_active ? 0 : 1;
  db.prepare(`UPDATE users SET is_active = ? WHERE id = ?`).run(next, id);

  return res.json({ ok: true, is_active: next });
});

// POST /admin/users/:id/reset-password
router.post("/users/:id/reset-password", async (req, res) => {
  const id = Number(req.params.id);
  const { newPassword } = req.body || {};

  if (!Number.isFinite(id)) return res.status(400).json({ ok: false, error: "ID inválido" });

  const pw = String(newPassword || "");
  if (!pw || pw.length < 6) {
    return res.status(400).json({ ok: false, error: "Senha inválida (mín. 6)" });
  }

  const u = db.prepare(`SELECT id FROM users WHERE id = ?`).get(id);
  if (!u) return res.status(404).json({ ok: false, error: "Usuário não encontrado" });

  const hash = await hashPassword(pw);
  db.prepare(`UPDATE users SET password_hash = ? WHERE id = ?`).run(hash, id);

  return res.json({ ok: true });
});

export default router;
