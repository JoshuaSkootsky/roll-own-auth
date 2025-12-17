import { Database } from 'bun:sqlite'
import { createAuthService } from './src/auth-service'
import type { AuthConfig } from './src/auth-service'
import { createServer } from './src/server-factory'

// Initialize DB
const db = new Database('db.sqlite')
db.run(await Bun.file('schema.sql').text())

// SALT is the number of rounds of salt to use in bcrypt
const SALT = 10

const JWT_EXPIRE_TIME = '7d'

// Bun automatically reads and loads the .env file into process.env.

// PEPPERS are used for rotating peppers
// otherwise, changing it once will break all existing passwords
const PEPPERS = (process.env.PEPPERS ?? '').split(',').filter(Boolean)

if (PEPPERS.length === 0) {
  console.error('❌ No PEPPERS defined in .env')
  process.exit(1)
}

// JWT_SECRET is the secret key for the JWT token - should be a long random string, like with web crypto
const JWT_SECRET = process.env.JWT_SECRET

if (!JWT_SECRET) {
  console.error('❌ JWT_SECRET not set in .env')
  process.exit(1)
}

// PORT is the port to run the server on
const PORT = Number(process.env.PORT ?? 3000)

// Create auth configuration
const authConfig: AuthConfig = {
  salt: SALT,
  jwtSecret: JWT_SECRET,
  jwtExpireTime: JWT_EXPIRE_TIME,
  peppers: PEPPERS
}

// Create auth service with dependencies
const authService = createAuthService(db, authConfig)

// Create and start server
const { server } = createServer(authService, { port: PORT })

// Export for potential testing use
export { authService, server }