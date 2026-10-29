import argon2 from 'argon2'

// Parâmetros do Argon2id conforme o enunciado
export const ARGON2_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 66560,   // 65 MiB (valor em KiB)
  timeCost: 3,         // 3 iterações
  parallelism: 4,      // 4 lanes
  hashLength: 32,      // 32 bytes => 43 caracteres em base64
  saltLength: 16       // 16 bytes => 22 caracteres em base64
}

export function hashPassword(plainPassword) {
  if (typeof plainPassword !== 'string' || plainPassword.length === 0) {
    throw new Error('Senha inválida para gerar hash')
  }
  return argon2.hash(plainPassword, ARGON2_OPTIONS)
}

export async function verifyPassword(storedHash, plainPassword) {
  if (typeof storedHash !== 'string' || !storedHash.startsWith('$argon2')) return false
  if (typeof plainPassword !== 'string') return false

  try {
    return await argon2.verify(storedHash, plainPassword)
  }
  catch {
    return false // hash malformado no banco
  }
}

export function needsRehash(storedHash) {
  return typeof storedHash === 'string' && argon2.needsRehash(storedHash, ARGON2_OPTIONS)
}