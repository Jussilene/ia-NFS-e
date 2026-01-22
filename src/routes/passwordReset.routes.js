// src/routes/passwordReset.routes.js
import crypto from "crypto";
import express from "express";
import nodemailer from "nodemailer";

// ✅ usa o store real do projeto
import { findUserByEmail, updatePasswordByEmail } from "../utils/usersStore.js";

// ✅ tokens
import { createResetToken, consumeResetToken, findResetToken } from "../utils/resetTokensStore.js";

const router = express.Router();

// --------------------------------------------------
// SMTP
// --------------------------------------------------
function makeTransport() {
  const host = String(process.env.SMTP_HOST || "").trim();
  const port = Number(process.env.SMTP_PORT || 587);
  const secure = String(process.env.SMTP_SECURE || "false") === "true";
  const user = String(process.env.SMTP_USER || "").trim();
  const pass = String(process.env.SMTP_PASS || "").trim();

  console.log("[SMTP] host:", host, "port:", port, "secure:", secure, "user:", user ? "(ok)" : "(vazio)");

  return nodemailer.createTransport({
    host,
    port,
    secure,
    auth: { user, pass },

    // ✅ força TLS quando for 587 (STARTTLS)
    requireTLS: !secure,

    // ✅ ISSO resolve o erro: "self-signed certificate in certificate chain"
    tls: {
      rejectUnauthorized: false,
      minVersion: "TLSv1.2",
    },

    logger: true,
    debug: true,
  });
}


// --------------------------------------------------
// POST /auth/forgot-password
// --------------------------------------------------
router.post("/forgot-password", async (req, res) => {
  const email = String(req.body?.email || "").trim().toLowerCase();

  // resposta neutra (segurança)
  const okMsg = {
    ok: true,
    message: "Se o e-mail existir, enviaremos um link de recuperação.",
  };

  try {
    if (!email) return res.status(200).json(okMsg);

    // ✅ 1) valida se o usuário existe no SQLite
    const user = await findUserByEmail(email);
    if (!user) {
      console.log("[forgot-password] usuário NÃO encontrado para:", email);
      return res.status(200).json(okMsg);
    }
    console.log("[forgot-password] usuário encontrado:", user.email);

    // ✅ 2) cria token
    const token = crypto.randomBytes(32).toString("hex");
    const expiresAt = Date.now() + 30 * 60 * 1000;

    await createResetToken({
      userId: user.id || user.email,
      email,
      token,
      expiresAt,
    });

    const base = (process.env.APP_BASE_URL || "http://localhost:3000").replace(/\/+$/, "");
    const link = `${base}/reset.html?token=${encodeURIComponent(token)}`;

    // ✅ 3) cria transport e verifica conexão/credenciais ANTES de enviar
    const transport = makeTransport();

    try {
      await transport.verify();
      console.log("[SMTP] verify OK");
    } catch (e) {
      console.error("[SMTP] verify FALHOU:", e?.message || e);
      // não quebra o front (neutro), mas você verá o motivo exato no terminal
      return res.status(200).json(okMsg);
    }

    // ✅ 4) envia e loga resultado
    const info = await transport.sendMail({
      from: process.env.MAIL_FROM || process.env.SMTP_USER,
      to: email, // ✅ SEMPRE pro e-mail digitado
      subject: "Recuperação de senha — NFSe Emissor",
      html: `
        <div style="font-family:Arial,sans-serif;line-height:1.5">
          <h2>Recuperação de senha</h2>
          <p>Recebemos um pedido para redefinir sua senha.</p>
          <p>Para criar uma nova senha, clique no link abaixo (válido por 30 minutos):</p>
          <p><a href="${link}">${link}</a></p>
          <p>Se você não solicitou isso, ignore este e-mail.</p>
        </div>
      `,
    });

    console.log("[SMTP] sendMail OK:", {
      messageId: info?.messageId,
      accepted: info?.accepted,
      rejected: info?.rejected,
      response: info?.response,
    });

    return res.status(200).json(okMsg);
  } catch (err) {
    console.error("forgot-password ERRO GERAL:", err?.message || err);
    return res.status(200).json(okMsg);
  }
});

// --------------------------------------------------
// POST /auth/reset-password
// --------------------------------------------------
router.post("/reset-password", async (req, res) => {
  try {
    const token = String(req.body?.token || "").trim();
    const newPassword = String(req.body?.newPassword || "");

    if (!token || newPassword.length < 6) {
      return res.status(400).json({
        ok: false,
        message: "Token inválido ou senha muito curta (mínimo 6 caracteres).",
      });
    }

    const rec = await findResetToken(token);
    if (!rec) return res.status(400).json({ ok: false, message: "Token inválido." });

    if (Date.now() > rec.expiresAt) {
      await consumeResetToken(token);
      return res.status(400).json({ ok: false, message: "Token expirado. Solicite novamente." });
    }

    await updatePasswordByEmail(rec.email, newPassword);
    await consumeResetToken(token);

    return res.json({ ok: true, message: "Senha alterada com sucesso. Faça login." });
  } catch (err) {
    console.error("reset-password:", err);
    return res.status(500).json({ ok: false, message: "Erro ao redefinir senha." });
  }
});

export default router;
