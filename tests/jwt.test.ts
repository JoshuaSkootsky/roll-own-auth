import { describe, test, expect, beforeEach, afterAll } from 'bun:test'
import { verify } from 'jsonwebtoken'
import { 
  makeLoginRequest, 
  makeAuthenticatedRequest, 
  expectJwtResponse,
  generateValidUserData,
  cleanUsersTable,
  createTestUser 
} from './utils'
import { TEST_BASE_URL, TEST_JWT_SECRET } from './setup'

describe('JWT Authentication Tests', () => {
  beforeEach(() => {
    cleanUsersTable()
  })

  describe('JWT Token Generation', () => {
    test('should return JWT token on successful login', async () => {
      const userData = generateValidUserData()
      await createTestUser(userData.username, userData.password)
      
      const loginResult = await makeLoginRequest(userData.username, userData.password)
      
      expect(loginResult.status).toBe(200)
      expectJwtResponse(loginResult, true, 'Login successful.')
      expect(loginResult.data.token).toBeDefined()
      expect(typeof loginResult.data.token).toBe('string')
    })

    test('should not return token on failed login - wrong password', async () => {
      const userData = generateValidUserData()
      await createTestUser(userData.username, userData.password)
      
      const loginResult = await makeLoginRequest(userData.username, 'wrongpassword')
      
      expect(loginResult.status).toBe(400)
      expect(loginResult.data.success).toBe(false)
      expect(loginResult.data.token).toBeUndefined()
    })

    test('should not return token on failed login - user not found', async () => {
      const userData = generateValidUserData()
      
      const loginResult = await makeLoginRequest(userData.username, userData.password)
      
      expect(loginResult.status).toBe(400)
      expect(loginResult.data.success).toBe(false)
      expect(loginResult.data.token).toBeUndefined()
    })
  })

  describe('JWT Token Validation', () => {
    test('should generate valid JWT token that can be decoded', async () => {
      const userData = generateValidUserData()
      await createTestUser(userData.username, userData.password)
      
      const loginResult = await makeLoginRequest(userData.username, userData.password)
      const token = loginResult.data.token!
      
      // Decode and verify token structure
      const decoded = verify(token, TEST_JWT_SECRET || process.env.JWT_SECRET!) as any
      expect(decoded.username).toBe(userData.username)
      expect(decoded.id).toBeDefined()
      expect(typeof decoded.id).toBe('number')
      expect(decoded.iat).toBeDefined() // issued at
      expect(decoded.exp).toBeDefined() // expiration
    })

    test('should reject token with wrong secret', async () => {
      const userData = generateValidUserData()
      await createTestUser(userData.username, userData.password)
      
      const loginResult = await makeLoginRequest(userData.username, userData.password)
      const token = loginResult.data.token!
      
      expect(() => verify(token, 'wrong-secret')).toThrow()
    })

    test('should reject malformed token', async () => {
      expect(() => verify('not-a-valid-jwt-token', TEST_JWT_SECRET || process.env.JWT_SECRET!)).toThrow()
    })
  })

  describe('Protected Routes', () => {
    test('should access protected route with valid JWT', async () => {
      const userData = generateValidUserData()
      await createTestUser(userData.username, userData.password)
      
      const loginResult = await makeLoginRequest(userData.username, userData.password)
      const token = loginResult.data.token!
      
      const profileResult = await makeAuthenticatedRequest('/profile', token)
      
      expect(profileResult.status).toBe(200)
      expect(profileResult.data.success).toBe(true)
      expect(profileResult.data.message).toBe(`Hello, ${userData.username}!`)
    })

    test('should reject protected route access without Authorization header', async () => {
      const response = await fetch(`${TEST_BASE_URL}/profile`)
      const result = await response.json() as { success: boolean; message: string }
      
      expect(response.status).toBe(401)
      expect(result.success).toBe(false)
      expect(result.message).toBe('Unauthorized')
    })

    test('should reject protected route access with malformed Authorization header', async () => {
      const response = await fetch(`${TEST_BASE_URL}/profile`, {
        headers: { 'Authorization': 'InvalidFormat token123' }
      })
      const result = await response.json() as { success: boolean; message: string }
      
      expect(response.status).toBe(401)
      expect(result.success).toBe(false)
      expect(result.message).toBe('Unauthorized')
    })

    test('should reject protected route access with invalid token', async () => {
      const response = await fetch(`${TEST_BASE_URL}/profile`, {
        headers: { 'Authorization': 'Bearer invalid-token' }
      })
      const result = await response.json() as { success: boolean; message: string }
      
      expect(response.status).toBe(401)
      expect(result.success).toBe(false)
      expect(result.message).toBe('Unauthorized')
    })

    test('should reject protected route access with expired token', async () => {
      // Create an expired token (this is test-only)
      const { sign } = require('jsonwebtoken')
      const expiredToken = sign(
        { username: 'testuser', id: 1 },
        TEST_JWT_SECRET || process.env.JWT_SECRET!,
        { expiresIn: '-1h' } // expired 1 hour ago
      )
      
      const response = await fetch(`${TEST_BASE_URL}/profile`, {
        headers: { 'Authorization': `Bearer ${expiredToken}` }
      })
      const result = await response.json() as { success: boolean; message: string }
      
      expect(response.status).toBe(401)
      expect(result.success).toBe(false)
      expect(result.message).toBe('Unauthorized')
    })

    test('should reject protected route with empty token', async () => {
      const response = await fetch(`${TEST_BASE_URL}/profile`, {
        headers: { 'Authorization': 'Bearer ' }
      })
      const result = await response.json() as { success: boolean; message: string }
      
      expect(response.status).toBe(401)
      expect(result.success).toBe(false)
      expect(result.message).toBe('Unauthorized')
    })
  })

  describe('Complete JWT Flow', () => {
    test('should complete full authentication flow: signup -> login -> protected access', async () => {
      const userData = generateValidUserData()
      
      // Step 1: Signup (using existing utility)
      await createTestUser(userData.username, userData.password)
      
      // Step 2: Login to get JWT
      const loginResult = await makeLoginRequest(userData.username, userData.password)
      expect(loginResult.data.token).toBeDefined()
      
      // Step 3: Access protected route with JWT
      const profileResult = await makeAuthenticatedRequest('/profile', loginResult.data.token!)
      expect(profileResult.status).toBe(200)
      expect(profileResult.data.message).toBe(`Hello, ${userData.username}!`)
      
      // Step 4: Token can be reused for multiple requests
      const secondProfileResult = await makeAuthenticatedRequest('/profile', loginResult.data.token!)
      expect(secondProfileResult.status).toBe(200)
      expect(secondProfileResult.data.message).toBe(`Hello, ${userData.username}!`)
    })
  })

  describe('JWT Security Tests', () => {
    test('should reject tampered JWT tokens', async () => {
      const userData = generateValidUserData()
      await createTestUser(userData.username, userData.password)
      
      const loginResult = await makeLoginRequest(userData.username, userData.password)
      const token = loginResult.data.token!
      
      // Tamper with the token by changing a character
      const tamperedToken = token.slice(0, -1) + 'x'
      
      const response = await fetch(`${TEST_BASE_URL}/profile`, {
        headers: { 'Authorization': `Bearer ${tamperedToken}` }
      })
      const result = await response.json() as { success: boolean; message: string }
      
      expect(response.status).toBe(401)
      expect(result.success).toBe(false)
      expect(result.message).toBe('Unauthorized')
    })
  })
})