import { describe, test, expect, beforeEach } from 'bun:test'
import { startTestServer } from './test-server-helpers'
import { cleanUsersTable, createTestUser, userExists, getUserPasswordHash, countUsers } from './utils'
import { TEST_PORT, TEST_DB_PATH } from './setup'

describe('Authentication Functions', () => {
  let server: any

  beforeEach(async () => {
    cleanUsersTable()
    server = await startTestServer(0, TEST_DB_PATH) // port 0 = any available port for unit tests
  })

  describe('signUp function', () => {
    test('should create new user with valid data', async () => {
      const username = 'testuser123'
      const password = 'testpass123'
      
      const result = await server.signUp(username, password)
      
      expect(result.success).toBe(true)
      expect(result.message).toBe('User created.')
      expect(userExists(username)).toBe(true)
      expect(countUsers()).toBe(1)
    })

    test('should hash password using bcrypt', async () => {
      const username = 'testuser456'
      const password = 'testpass456'
      
      await server.signUp(username, password)
      const hashedPassword = getUserPasswordHash(username)
      
      expect(hashedPassword).toBeDefined()
      expect(hashedPassword).not.toBe(password) // Should not be plain text
      expect(hashedPassword!.length).toBeGreaterThan(50) // bcrypt hash length
    })

    test('should reject duplicate usernames', async () => {
      const username = 'duplicateuser'
      const password1 = 'pass123'
      const password2 = 'pass456'
      
      // First user should succeed
      const result1 = await server.signUp(username, password1)
      expect(result1.success).toBe(true)
      
      // Second user with same username should fail
      const result2 = await server.signUp(username, password2)
      expect(result2.success).toBe(false)
      expect(result2.message).toBe('Username already exists.')
      expect(countUsers()).toBe(1) // Only one user should exist
    })

    test('should handle database errors gracefully', async () => {
      // Try to create user with invalid data that might cause DB error
      const veryLongUsername = 'a'.repeat(1000)
      const password = 'validpassword123'
      
      const result = await server.signUp(veryLongUsername, password)
      
      // Should handle error gracefully (either success or controlled failure)
      expect(typeof result.success).toBe('boolean')
      expect(typeof result.message).toBe('string')
    })
  })

  describe('login function', () => {
    beforeEach(async () => {
      // Create test user for login tests
      await createTestUser('loginuser', 'loginpass123')
    })

    test('should authenticate with correct credentials', async () => {
      const result = await server.login('loginuser', 'loginpass123')
      
      expect(result.success).toBe(true)
      expect(result.message).toBe('Login successful.')
    })

    test('should reject wrong password', async () => {
      const result = await server.login('loginuser', 'wrongpassword')
      
      expect(result.success).toBe(false)
      expect(result.message).toBe('Invalid password.')
    })

    test('should handle non-existent user', async () => {
      const result = await server.login('nonexistent', 'anypassword')
      
      expect(result.success).toBe(false)
      expect(result.message).toBe('User not found.')
    })

    test('should properly compare bcrypt hashes', async () => {
      // Create user with known password
      await server.signUp('hashtest', 'knownpassword123')
      
      // Should login successfully
      const result = await server.login('hashtest', 'knownpassword123')
      expect(result.success).toBe(true)
      
      // Should fail with wrong password
      const result2 = await server.login('hashtest', 'wrongpassword')
      expect(result2.success).toBe(false)
    })
  })

  describe('findUser function', () => {
    beforeEach(async () => {
      await createTestUser('findtest', 'findpass123')
    })

    test('should return user data for existing user', async () => {
      const user = server.findUser('findtest')
      
      expect(user).toBeDefined()
      expect(user!.username).toBe('findtest')
      expect(user!.id).toBeGreaterThan(0)
      expect(user!.password_hash).toBeDefined()
    })

    test('should return undefined for non-existent user', async () => {
      const user = server.findUser('nonexistent')
      
      expect(user).toBeUndefined()
    })

    test('should not include password in plain text', async () => {
      const user = server.findUser('findtest')
      
      expect(user).toBeDefined()
      expect(user!.password_hash).not.toBe('findpass123') // Should be hashed
    })
  })

  describe('Database Operations', () => {
    test('should maintain user count correctly', async () => {
      expect(countUsers()).toBe(0)
      
      await server.signUp('user1', 'pass1')
      expect(countUsers()).toBe(1)
      
      await server.signUp('user2', 'pass2')
      expect(countUsers()).toBe(2)
      
      // Duplicate user shouldn't increase count
      await server.signUp('user1', 'pass3')
      expect(countUsers()).toBe(2)
    })

    test('should handle concurrent user creation', async () => {
      const promises = Array.from({ length: 5 }, (_, i) => 
        server.signUp(`concurrent${i}`, `pass${i}`)
      )
      
      const results = await Promise.all(promises)
      
      expect(results.every(r => r.success)).toBe(true)
      expect(countUsers()).toBe(5)
    })
  })

  describe('Password Security', () => {
    test('should generate different hashes for same password', async () => {
      const password = 'samepassword'
      
      await server.signUp('user1', password)
      await server.signUp('user2', password)
      
      const hash1 = getUserPasswordHash('user1')
      const hash2 = getUserPasswordHash('user2')
      
      expect(hash1).toBeDefined()
      expect(hash2).toBeDefined()
      expect(hash1).not.toBe(hash2) // Different salts should produce different hashes
    })

    test('should handle complex passwords', async () => {
      const complexPassword = 'ComplexP@ssw0rd!#$%&*()_+-='
      
      const result = await server.signUp('complexuser', complexPassword)
      
      expect(result.success).toBe(true)
      expect(userExists('complexuser')).toBe(true)
    })
  })
})