import prisma from '../database/client.js'
import jwt from 'jsonwebtoken'
import { hashPassword, verifyPassword, needsRehash } from '../utils/password.js'

const controller = {}     // Objeto vazio

// Campos que podem ser devolvidos ao cliente.
// OWASP Top 10:2025 A01 - Falha no Controle de Acesso:
// o campo password (mesmo em hash) não faz parte da resposta.
const PUBLIC_FIELDS = { id: true, username: true, email: true, is_admin: true }

controller.create = async function(req, res) {
  try {

    // OWASP Top 10:2025 A01 - Falha no Controle de Acesso:
    // a atribuição em massa foi eliminada: apenas username, email e password
    // são lidos do corpo da requisição, e is_admin é forçado para false.
    // OWASP Top 10:2025 A04 - Falhas de Criptografia:
    // password é persistido como hash Argon2id (m=66560, t=3, p=4), nunca em texto puro.
    const { username, email, password } = req.body ?? {}

    if (!username || !email || !password) {
      return res.status(422).json({ error: 'username, email e password são obrigatórios' })
    }

    if (String(password).length < 8) {
      return res.status(422).json({ error: 'A senha deve ter pelo menos 8 caracteres' })
    }

    await prisma.user.create({
      data: {
        username,
        email,
        password: await hashPassword(password),  // Argon2id
        is_admin: false
      }
    })

    // HTTP 201: Created
    res.status(201).end()
  }
  catch(error) {
    // P2002: violação de campo único (username ou email já cadastrado)
    if(error?.code === 'P2002') {
      return res.status(409).json({ error: 'username ou email já cadastrado' })
    }

    console.error(error)

    // HTTP 500: Internal Server Error
    res.status(500).end()
  }
}

controller.retrieveAll = async function(req, res) {
  try {
    // OWASP Top 10:2025 A01 - Falha no Controle de Acesso:
    // a consulta passou a usar select explícito, sem o campo password.
    // OWASP Top 10:2025 A04 - Falhas de Criptografia:
    // nenhum hash de senha é exposto na listagem.
    const result = await prisma.user.findMany({
      select: PUBLIC_FIELDS
    })

    // HTTP 200: OK (implícito)
    res.send(result)
  }
  catch(error) {
    console.error(error)

    // HTTP 500: Internal Server Error
    res.status(500).end()
  }
}

controller.retrieveOne = async function(req, res) {
  try {
    const id = Number(req.params.id)

    // ID inválido (não numérico) ~> HTTP 400: Bad Request
    if(! Number.isInteger(id)) return res.status(400).end()

    // OWASP Top 10:2025 A01 - Falha no Controle de Acesso:
    // a consulta por ID continua existindo, mas o select impede
    // que o campo password seja devolvido ao cliente.
    const result = await prisma.user.findUnique({
      where: { id },
      select: PUBLIC_FIELDS
    })

    // Encontrou ~> retorna HTTP 200: OK (implícito)
    if(result) res.send(result)
    // Não encontrou ~> retorna HTTP 404: Not Found
    else res.status(404).end()
  }
  catch(error) {
    console.error(error)

    // HTTP 500: Internal Server Error
    res.status(500).end()
  }
}

controller.update = async function(req, res) {
  try {
    const id = Number(req.params.id)

    // ID inválido (não numérico) ~> HTTP 400: Bad Request
    if(! Number.isInteger(id)) return res.status(400).end()

    // OWASP Top 10:2025 A01 - Falha no Controle de Acesso:
    // a atribuição em massa foi eliminada: o cliente só consegue alterar
    // username, email e password. is_admin não é aceito por este endpoint.
    const { username, email, password } = req.body ?? {}
    const data = {}

    if(username !== undefined) data.username = username
    if(email !== undefined) data.email = email

    // OWASP Top 10:2025 A04 - Falhas de Criptografia:
    // a nova senha também é gravada como hash Argon2id, nunca em texto puro.
    // O hash só é gerado quando uma nova senha é efetivamente enviada.
    if(password !== undefined && password !== '') {
      if(String(password).length < 8) {
        return res.status(422).json({ error: 'A senha deve ter pelo menos 8 caracteres' })
      }

      data.password = await hashPassword(password)
    }

    if(Object.keys(data).length === 0) {
      return res.status(422).json({ error: 'Nenhum campo válido para atualizar' })
    }

    await prisma.user.update({
      where: { id },
      data
    })

    // Encontrou e atualizou ~> HTTP 204: No Content
    res.status(204).end()
  }
  catch(error) {
    // P2025: registro não encontrado
    // (o prisma.user.update lança exceção, não retorna null)
    if(error?.code === 'P2025') return res.status(404).end()

    // P2002: violação de campo único (username ou email já cadastrado)
    if(error?.code === 'P2002') {
      return res.status(409).json({ error: 'username ou email já cadastrado' })
    }

    console.error(error)

    // HTTP 500: Internal Server Error
    res.status(500).end()
  }
}

controller.delete = async function(req, res) {
  try {
    const id = Number(req.params.id)

    // ID inválido (não numérico) ~> HTTP 400: Bad Request
    if(! Number.isInteger(id)) return res.status(400).end()

    await prisma.user.delete({
      where: { id }
    })

    // Encontrou e excluiu ~> HTTP 204: No Content
    res.status(204).end()
  }
  catch(error) {
    if(error?.code === 'P2025') {
      // Não encontrou e não excluiu ~> HTTP 404: Not Found
      res.status(404).end()
    }
    else {
      // Outros tipos de erro
      console.error(error)

      // HTTP 500: Internal Server Error
      res.status(500).end()
    }
  }
}

controller.login = async function(req, res) {
  try {

      const { username, email, password } = req.body ?? {}

      // Sem credencial informada ~> HTTP 400: Bad Request
      if((! username && ! email) || ! password) {
        return res.status(400).json({ error: 'Informe username ou email e a senha' })
      }

      // Busca o usuário no BD usando o valor dos campos
      // "username" OU "email"
      const user = await prisma.user.findFirst({
        where: {
          OR: [
            ...(username ? [{ username }] : []),
            ...(email ? [{ email }] : [])
          ]
        }
      })

      // Se o usuário não for encontrado, retorna
      // HTTP 401: Unauthorized
      if(! user) return res.status(401).end()

      // Usuário encontrado, vamos conferir a senha
      // OWASP Top 10:2025 A07 - Falhas de Autenticação:
      // a credencial fixa admin/admin123 foi removida; a autenticação
      // depende exclusivamente da senha cadastrada para o usuário.
      // OWASP Top 10:2025 A04 - Falhas de Criptografia:
      // a conferência é feita pelo argon2.verify, que lê o sal e os
      // parâmetros (m, t, p) de dentro do próprio hash armazenado.
      // A senha recebida nunca é comparada com === contra o valor do banco.
      const passwordIsValid = await verifyPassword(user.password, password)

      // Se a senha estiver errada, retorna
      // HTTP 401: Unauthorized
      if(! passwordIsValid) return res.status(401).end()

      // OWASP Top 10:2025 A04 - Falhas de Criptografia:
      // se o hash foi gerado com parâmetros antigos, ele é regravado
      // com os parâmetros atuais do Argon2id (rehash transparente).
      if(needsRehash(user.password)) {
        await prisma.user.update({
          where: { id: user.id },
          data: { password: await hashPassword(password) }
        })
      }

      // Usuário e senha OK, passamos ao procedimento de gerar o token
      // OWASP Top 10:2025 A04 - Falhas de Criptografia:
      // o JWT passou a incluir apenas sub, username e is_admin.
      // A senha (e o hash) não é mais assinada dentro do token, pois
      // a assinatura garante integridade, mas não oculta o conteúdo.
      const token = jwt.sign(
        {
          sub: String(user.id),      // Identificador do usuário
          username: user.username,
          is_admin: user.is_admin
        },
        process.env.TOKEN_SECRET,    // Senha para criptografar o token
        { expiresIn: '24h' }         // Prazo de validade do token
      )

      // Formamos o cookie para enviar ao front-end
      res.cookie(process.env.AUTH_COOKIE_NAME, token, {
        httpOnly: true, // O cookie ficará inacessível para o JS no front-end
        secure: true,   // O cookie será criptografado em conexões https
        sameSite: 'None',
        path: '/',
        maxAge: 24 * 60 * 60 * 1000  // 24h (1000 ms por segundo)
      })

      // OWASP Top 10:2025 A04 - Falhas de Criptografia:
      // a resposta devolve o usuário sem o campo password.
      const { password: _omit, ...safeUser } = user

      // Retorna o token e o usuário autenticado com
      // HTTP 200: OK (implícito)
      res.send({ token, user: safeUser })

  }
  catch(error) {
    console.error(error)

    // HTTP 500: Internal Server Error
    res.status(500).end()
  }
}

controller.me = function(req, res) {
  // Retorna as informações do usuário autenticado
  // OWASP Top 10:2025 A04 - Falhas de Criptografia:
  // req.authUser vem do payload do JWT, que não carrega mais a senha.
  // HTTP 200: OK (implícito)
  res.send(req?.authUser)
}

export default controller