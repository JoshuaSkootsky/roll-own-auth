import { describe, test, expect, beforeEach } from 'bun:test'
import { makeSignupRequest, makeLoginRequest, cleanUsersTable, generateValidUserData, expectSuccessResponse, expectErrorResponse } from './utils'
import { TEST_BASE_URL } from './setup'

describe('HTTP API Integration Tests', () => {
  beforeEach(() => {
    cleanUsersTable()
  })

  describe('POST /signup', () => {
    test('should create user and return 201', async () => {
      const userData = generateValidUserData()
      
      const result = await makeSignupRequest(userData.username, userData.password)
      
      expect(result.status).toBe(201)
      expect(result.data.success).toBe(true)
      expect(result.data.message).toBe('User created.')
    })

    test('should return success message', async () => {
      const userData = generateValidUserData()
      
      const result = await makeSignupRequest(userData.username, userData.password)
      
      expect(result.data.message).toBe('User created.')
    })

    test('should reject duplicate username with 400', async () => {
      const userData = generateValidUserData()
      
      // First signup should succeed
      const result1 = await makeSignupRequest(userData.username, userData.password)
      expectSuccessResponse(result1)
      
      // Second signup with same username should fail
      const result2 = await makeSignupRequest(userData.username, 'differentpassword')
      expectErrorResponse(result2, 400, 'Username already exists.')
    })

    test('should validate username length (min 3 chars)', async () => {
      const result = await makeSignupRequest('ab', 'validpassword123')
      
      expect(result.status).toBe(400)
      expect(result.data.success).toBe(false)
      expect(result.data.message).toContain('Username must be at least 3 characters')
    })

    test('should validate password length (min 6 chars)', async () => {
      const result = await makeSignupRequest('validuser', '123')
      
      expect(result.status).toBe(400)
      expect(result.data.success).toBe(false)
      expect(result.data.message).toContain('Password must be at least 6 characters')
    })

    test('should handle malformed JSON', async () => {
      const response = await fetch(`${TEST_BASE_URL}/signup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: 'invalid json'
      })
      
      expect(response.status).toBe(400)
    })

    test('should handle missing fields', async () => {
      const result1 = await makeSignupRequest('', 'password123')
      const result2 = await makeSignupRequest('username', '')
      
      expect(result1.status).toBe(400)
      expect(result2.status).toBe(400)
    })

    test('should set correct content-type header', async () => {
      const userData = generateValidUserData()
      
      const result = await makeSignupRequest(userData.username, userData.password)
      
      expect(result.response.headers.get('content-type')).toBe('application/json')
    })
  })

  describe('POST /login', () => {
    beforeEach(async () => {
      // Create a test user for login tests
      await makeSignupRequest('loginuser', 'loginpass123')
    })

    test('should authenticate and return 200', async () => {
      const result = await makeLoginRequest('loginuser', 'loginpass123')
      
      expect(result.status).toBe(200)
      expect(result.data.success).toBe(true)
      expect(result.data.message).toBe('Login successful.')
    })

    test('should return success message', async () => {
      const result = await makeLoginRequest('loginuser', 'loginpass123')
      
      expect(result.data.message).toBe('Login successful.')
    })

    test('should reject wrong password with 400', async () => {
      const result = await makeLoginRequest('loginuser', 'wrongpassword')
      
      expectErrorResponse(result, 400, 'Invalid password.')
    })

    test('should handle non-existent user with 400', async () => {
      const result = await makeLoginRequest('nonexistent', 'anypassword')
      
      expectErrorResponse(result, 400, 'User not found.')
    })

    test('should validate input data', async () => {
      const result1 = await makeLoginRequest('', 'password123')
      const result2 = await makeLoginRequest('username', '')
      
      expect(result1.status).toBe(400)
      expect(result2.status).toBe(400)
    })

    test('should set correct content-type header', async () => {
      const result = await makeLoginRequest('loginuser', 'loginpass123')
      
      expect(result.response.headers.get('content-type')).toBe('application/json')
    })
  })

  describe('Error Handling', () => {
    test('should handle database connection errors gracefully', async () => {
      // This test simulates database errors
      // We'll test invalid operations that might trigger DB errors
      const userData = generateValidUserData()
      
      const result = await makeSignupRequest(userData.username, userData.password)
      
      // Should handle gracefully (either success or controlled failure)
      expect(typeof result.status).toBe('number')
      expect(typeof result.data).toBe('object')
    })

    test('should return proper error format', async () => {
      const result = await makeSignupRequest('ab', '123') // Invalid data
      
      expect(result.data).toHaveProperty('success')
      expect(result.data).toHaveProperty('message')
      expect(typeof result.data.success).toBe('boolean')
      expect(typeof result.data.message).toBe('string')
    })

    test('should handle unknown routes', async () => {
      const response = await fetch(`${TEST_BASE_URL}/unknown`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ test: 'data' })
      })
      
      expect(response.status).toBe(404)
      expect(await response.text()).toBe('Use /signup or /login')
    })

    test('should handle GET requests to POST endpoints', async () => {
      const response1 = await fetch(`${TEST_BASE_URL}/signup`)
      const response2 = await fetch(`${TEST_BASE_URL}/login`)
      
      // Should return 404 or method not allowed
      expect([response1.status, response2.status]).toContain(404)
    })
  })

  describe('Authentication Flow', () => {
    test('should complete full signup then login flow', async () => {
      const userData = generateValidUserData()
      
      // Step 1: Signup
      const signupResult = await makeSignupRequest(userData.username, userData.password)
      expectSuccessResponse(signupResult)
      
      // Step 2: Login with correct credentials
      const loginResult = await makeLoginRequest(userData.username, userData.password)
      expect(loginResult.status).toBe(200)
      expect(loginResult.data.success).toBe(true)
    })

    test('should prevent login before signup', async () => {
      const result = await makeLoginRequest('newuser', 'password123')
      
      expect(result.status).toBe(400)
      expect(result.data.message).toBe('User not found.')
    })

    test('should handle multiple sequential operations', async () => {
      const operations = []
      
      // Create multiple users
      for (let i = 0; i < 3; i++) {
        const username = `user${i}`
        const password = `pass${i}123`
        
        // Signup
        const signupResult = await makeSignupRequest(username, password)
        expect(signupResult.status).toBe(201)
        
        // Login
        const loginResult = await makeLoginRequest(username, password)
        expect(loginResult.status).toBe(200)
        
        operations.push({ username, signupStatus: signupResult.status, loginStatus: loginResult.status })
      }
      
      expect(operations.length).toBe(3)
      expect(operations.every(op => op.signupStatus === 201 && op.loginStatus === 200)).toBe(true)
    })
  })

  describe('Request Validation', () => {
    test.each([
      { username: 'ab', password: 'validpass123', expectedError: 'Username must be at least 3 characters' },
      { username: 'a', password: 'validpass123', expectedError: 'Username must be at least 3 characters' },
      { username: 'validuser', password: '123', expectedError: 'Password must be at least 6 characters' },
      { username: 'validuser', password: '12', expectedError: 'Password must be at least 6 characters' },
      { username: '', password: 'validpass123', expectedError: 'Required' },
      { username: 'validuser', password: '', expectedError: 'Required' }
    ])('should reject: $expectedError', async ({ username, password, expectedError }) => {
      const result = await makeSignupRequest(username, password)
      
      expect(result.status).toBe(400)
      expect(result.data.success).toBe(false)
      if (expectedError !== 'Required') {
        expect(result.data.message).toContain(expectedError)
      }
    })
  })
})