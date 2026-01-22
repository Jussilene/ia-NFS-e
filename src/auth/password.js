// src/auth/password.js
import bcrypt from "bcryptjs";

export async function hashPassword(plain) {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(String(plain), salt);
}

export async function verifyPassword(plain, hash) {
  return bcrypt.compare(String(plain), String(hash || ""));
}
