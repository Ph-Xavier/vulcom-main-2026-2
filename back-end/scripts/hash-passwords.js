import prisma from '../src/database/client.js'
import { hashPassword } from '../src/utils/password.js'

async function main() {
  const users = await prisma.user.findMany({
    select: { id: true, username: true, password: true }
  })

  let migrated = 0

  for (const user of users) {
    const alreadyHashed = typeof user.password === 'string' && user.password.startsWith('$argon2')
    if (alreadyHashed) continue

    await prisma.user.update({
      where: { id: user.id },
      data: { password: await hashPassword(user.password) }
    })

    console.log(`Senha protegida: ${user.username}`)
    migrated++
  }

  console.log(`Total migrado: ${migrated} de ${users.length}`)
}

main()
  .catch((error) => {
    console.error(error)
    process.exitCode = 1
  })
  .finally(() => prisma.$disconnect())