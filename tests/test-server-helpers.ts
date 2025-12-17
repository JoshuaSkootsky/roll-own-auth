import { hash, compare } from 'bcrypt'
import { sign, verify } from 'jsonwebtoken'
import { Database } from 'bun:sqlite'
import { AuthBody } from '../parse'

// Test configuration
const SALT = 10

// Test environment variables - should be set in setup.ts
const PEPPERS = (process.env.PEPPERS ?? '').split(',').filter(Boolean)
const JWT_SECRET = process.env.JWT_SECRET || 'test-jwt-secret-key-for-testing'

if (PEPPERS.length === 0) {
  console.error('❌ No PEPPERS defined in test environment')
  process.exit(1)
}

// UserType is a user in the database (as defined in schema.sql)
type UserType = {
  id: number
  username: string
  password_hash: string
}

// Test server factory function
export async function startTestServer(port: number, dbPath: string) {
  // Initialize test database
  const db = new Database(dbPath)
  
  // Test-specific findUser function
  const findUser = (username: string): UserType | undefined => {
    const result = db.prepare('SELECT * FROM users WHERE username = ?').get(username)
    return result ? result as UserType : undefined
  }

  // Test-specific hashPassword function
  const hashPassword = async (password: string): Promise<string> => {
    return hash(PEPPERS[0] + password, SALT)
  }

  // Test-specific verifyPassword function
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

  // Test-specific signUp function
  const signUp = async (username: string, password: string) => {
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

  // Test-specific login function
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
      expiresIn: '7d',
    })

    return { success: true, message: 'Login successful.', token }
  }

  // Test-specific authenticate middleware
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

  // Create test server
  const server = Bun.serve({
    port,
    fetch: async (req) => {
      try {
        const url = new URL(req.url)
        const path = url.pathname
        const method = req.method

        // signup route
        if (path === '/signup' && method === 'POST') {
          const parsed = await AuthBody(req)
          if (!parsed.success) {
            return new Response(JSON.stringify({
              success: false,
              message: parsed.error.issues?.map(i => i.message).join(', ') || 'Validation error'
            }), {
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
            return new Response(JSON.stringify({
              success: false,
              message: parsed.error.issues?.map(i => i.message).join(', ') || 'Validation error'
            }), {
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
      } catch (error) {
        // Handle JSON parsing errors and other request errors
        return new Response(JSON.stringify({
          success: false,
          message: 'Invalid request format'
        }), {
          headers: { 'Content-Type': 'application/json' },
          status: 400,
        })
      }
    }
  })

  console.log(`Test server listening on port ${port}`)
  
  return {
    server,
    stop: () => {
      db.close()
      server.stop()
    },
    // Export auth functions for unit testing
    signUp,
    login,
    findUser,
    getDb: () => db
  }
}