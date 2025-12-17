import { hash, compare } from 'bcrypt'
import { Database } from 'bun:sqlite'
import { AuthBody } from '../parse'

// Test configuration
const SALT = 10

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

  // Test-specific signUp function
  const signUp = async (username: string, password: string) => {
    const hashedPassword = await hash(password, SALT)
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

    const hash = user.password_hash
    const isValid = await compare(password, hash)
    if (!isValid) {
      return { success: false, message: 'Invalid password.' }
    }

    return { success: true, message: 'Login successful.' }
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

        // catch all
        return new Response('Use /signup or /login', { status: 404 })
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