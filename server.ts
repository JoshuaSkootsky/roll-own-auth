import { hash, compare } from 'bcrypt'
import { Database } from 'bun:sqlite'
import { verify, sign } from 'jsonwebtoken'

import { AuthBody } from './parse'

// Initialize DB
const db = new Database('db.sqlite')
db.run(await Bun.file('schema.sql').text())

// SALT is the number of rounds of salt  to use in bcrypt
const SALT = 10

const JWT_EXPIRE_TIME = '7d'

// Bun automatically reads and loads the .env file into process.env.

// PEPPER is used for bcryptconst
// PEPPERS are used for rotating peppers
// otherwise, changing it once will break all existing passwords
const PEPPERS = (process.env.PEPPERS ?? '').split(',').filter(Boolean)

if (PEPPERS.length === 0) {
  console.error('❌ No PEPPERS defined in .env')
  process.exit(1)
}

// JWT_SECRET is the secret key for the JWT token - should be a long random string, like with web crypto
const JWT_SECRET = process.env.JWT_SECRET

if (PEPPERS.length === 0 || !JWT_SECRET) {
  console.error('❌ PEPPERS or JWT_SECRET not set in .env')
  process.exit(1)
}

// PORT is the port to run the server on
const PORT = Number(process.env.PORT ?? 3000)

// UserType is a user in the database (as defined in schema.sql)
type UserType = {
  id: number
  username: string
  password_hash: string
}

// findUser returns a user by username
const findUser = (username: string): UserType | undefined => {
  return db.prepare('SELECT * FROM users WHERE username = ?').get(username) as
    | UserType
    | undefined
}

// 🔐 Hash with pepper
const hashPassword = async (password: string): Promise<string> => {
  return hash(PEPPERS[0] + password, SALT)
}

// 🔐 Verify password with peppers
const verifyPassword = async (
  password: string,
  hash: string
): Promise<{ isValid: boolean; usedPepper: string | null }> => {
  if (!hash) {
    return { isValid: false, usedPepper: null }
  }

for (const pepper of PEPPERS) {
    const isValid = await compare(pepper + password, hash)
    if (isValid) {
      return { isValid: true, usedPepper: pepper }
    }
  }
  return { isValid: false, usedPepper: null }
}

// signUp registers a new user
const signUp = async (username: string, password: string) => {
  // hashedPassword is stored in the database, not the plaintext password
  const hashedPassword = await hashPassword(password)
  try {
    db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run(
      username,
      hashedPassword
    )
    return { success: true, message: 'User created.' }
  } catch (err) {
    return { success: false, message: 'Username already exists.' }
  }
}

// login logic
const login = async (username: string, password: string) => {
  const user = findUser(username)

  if (!user) {
    return { success: false, message: 'User not found.' }
  }

  // Try all peppers
  const { isValid, usedPepper } = await verifyPassword(password, user.password_hash)
  if (!isValid) {
    return { success: false, message: 'Invalid password.' }
  }

  // check the pepper, upgrade to PEPPERS[0] (rotate out old peppers on log in)
  if (usedPepper !== PEPPERS[0]) {
    const newPasswordHash = await hashPassword(password)
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(newPasswordHash, user.id)
  }

  const token = sign({ username: user.username, id: user.id }, JWT_SECRET, {
    expiresIn: JWT_EXPIRE_TIME,
  })

  return { success: true, message: 'Login successful.', token }
}

// 🔍 Authenticate middleware (for protected routes)
const authenticate = (req: Request): { valid: boolean; user?: any } => {
  const auth = req.headers.get('Authorization')
  if (!auth || !auth.startsWith('Bearer ')) {
    return { valid: false }
  }

  const tokenParts = auth.split(' ')
  if (tokenParts.length !== 2) {
    return { valid: false }
  }
  
  const token = tokenParts[1]
  if (!token) {
    return { valid: false }
  }
  
  try {
    const decoded = verify(token, JWT_SECRET)
    return { valid: true, user: decoded }
  } catch (err) {
    return { valid: false }
  }
}

// server
const server = Bun.serve({
  port: PORT,
  fetch: async (req, res) => {
    // Log incoming requests
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`)
    const url = new URL(req.url)
    const path = url.pathname
    const method = req.method

    // signup route
    if (path === '/signup' && method === 'POST') {
      const parsed = await AuthBody(req)
      if (!parsed.success) {
        return new Response(JSON.stringify(parsed.error), {
          headers: { 'Content-Type': 'application/json' },
          status: 400,
        })
      }

      const { username, password } = parsed.data
      const result = await signUp(username, password)

      return new Response(JSON.stringify(result), {
        headers: { 'Content-Type': 'application/json' },
        status: result.success ? 201 : 400,
      })
    }

    // login route
    if (path === '/login' && method === 'POST') {
      const parsed = await AuthBody(req)
      if (!parsed.success) {
        return new Response(JSON.stringify(parsed.error), {
          headers: { 'Content-Type': 'application/json' },
          status: 400,
        })
      }

      const { username, password } = parsed.data
      const result = await login(username, password)

      return new Response(JSON.stringify(result), {
        headers: { 'Content-Type': 'application/json' },
        status: result.success ? 200 : 400,
      })
    }

    // 🔒 Protected route example
    if (path === '/profile' && method === 'GET') {
      const authResult = authenticate(req)
      if (!authResult.valid) {
        return new Response(
          JSON.stringify({ success: false, message: 'Unauthorized' }),
          { status: 401, headers: { 'Content-Type': 'application/json' } }
        )
      }
      return new Response(
        JSON.stringify({ success: true, message: `Hello, ${authResult.user.username}!` }),
        { status: 200, headers: { 'Content-Type': 'application/json' } }
      )
    }

    // catch all
    return new Response('Use /signup, /login, or /profile', { status: 404 })
  },
})

console.log(`Server listening on port ${PORT}`)
