import { Database } from 'bun:sqlite'
import { createAuthService } from '../src/auth-service'
import { createServer } from '../src/server-factory'
import { type AuthService, type AuthConfig } from '../src/auth-service'
import { TEST_JWT_SECRET, TEST_PEPPERS } from './setup'

export function createTestAuthService(db?: Database): AuthService {
  const testDb = db || new Database('./test_db.sqlite')
  
  const testConfig: AuthConfig = {
    salt: 10,
    jwtSecret: TEST_JWT_SECRET,
    jwtExpireTime: '7d',
    peppers: TEST_PEPPERS
  }
  
  return createAuthService(testDb, testConfig)
}

export function createTestServer(port: number, dbPath: string) {
  const testDb = new Database(dbPath)
  const authService = createTestAuthService(testDb)
  const server = createServer(authService, { port })
  
  return {
    server: server.server,
    authService: server.authService,
    stop: server.stop
  }
}

// Direct access to auth functions for unit testing
export function createTestAuthDirect(dbPath?: string): AuthService {
  const testDb = dbPath ? new Database(dbPath) : new Database('./test_db.sqlite')
  return createTestAuthService(testDb)
}