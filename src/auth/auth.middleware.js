// src/auth/auth.middleware.js
import { getSessionUser } from "./session.store.js";

export function requireAuth(req, res, next) {
  try {
    const user = getSessionUser(req);
    if (!user) return res.status(401).json({ ok: false, error: "Não autenticado" });

    req.user = user;

    // ✅ importante: mantém teu multi-tenant consistente
    req.userEmail = user.email;

    return next();
  } catch (err) {
    return res.status(500).json({ ok: false, error: "Erro de autenticação" });
  }
}

export function requireAdmin(req, res, next) {
  const role = String(req.user?.role || "").toUpperCase();
  if (role !== "ADMIN") {
    return res.status(403).json({ ok: false, error: "Acesso negado (ADMIN)" });
  }
  return next();
}
