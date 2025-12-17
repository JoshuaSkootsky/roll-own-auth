import { hash, compare } from 'bcrypt'
import { Database } from 'bun:sqlite'
import { AuthBody } from './parse'

// Initialize DB
const db = new Database('db.sqlite')
db.run(await Bun.file('schema.sql').text())

// SALT is the number of rounds of salt  to use
const SALT = 10

// PORT is the port to run the server on
const PORT = process.env.PORT || 3000

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

// signUp registers a new user
const signUp = async (username: string, password: string) => {
  // hashedPassword is stored in the database, not the plaintext password
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

// login route
const login = async (username: string, password: string) => {
  const user = findUser(username)

  if (!user) {
    return { success: false, message: 'User not found.' }
  }

  // hash from the database is compared
  // compare is the bcrypt library function
  const hash = user.password_hash
  const isValid = await compare(password, hash)
  if (!isValid) {
    return { success: false, message: 'Invalid password.' }
  }

  return { success: true, message: 'Login successful.' }
}


// server
const server = Bun.serve({
  port: PORT,
  fetch: async (req, res) => {
    // Log incoming requests
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
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



    // catch all
    return new Response('Use /signup or /login', { status: 404 })
  },
})

console.log(`Server listening on port ${PORT}`);