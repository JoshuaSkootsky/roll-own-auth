import { expect } from 'bun:test'
import { Database } from 'bun:sqlite'
import { hash } from 'bcrypt'
import { TEST_DB_PATH, TEST_BASE_URL } from './setup'

// API response types
export interface ApiResponse {
  success: boolean
  message: string
}

export interface TestApiResponse {
  status: number
  data: ApiResponse
  response: Response
}

const SALT = 10

// Test database utilities
export const getTestDb = () => new Database(TEST_DB_PATH)

export const cleanUsersTable = () => {
  const db = getTestDb()
  db.run('DELETE FROM users')
  db.close()
}

export const countUsers = (): number => {
  const db = getTestDb()
  const result = db.prepare('SELECT COUNT(*) as count FROM users').get() as {count: number}
  db.close()
  return result.count
}

export const userExists = (username: string): boolean => {
  const db = getTestDb()
  const result = db.prepare('SELECT COUNT(*) as count FROM users WHERE username = ?').get(username) as {count: number}
  db.close()
  return result.count > 0
}

export const createTestUser = async (username: string, password: string): Promise<void> => {
  const db = getTestDb()
  const hashedPassword = await hash(password, SALT)
  db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run(username, hashedPassword)
  db.close()
}

export const getUserPasswordHash = (username: string): string | undefined => {
  const db = getTestDb()
  const result = db.prepare('SELECT password_hash FROM users WHERE username = ?').get(username) as {password_hash: string} | undefined
  db.close()
  return result?.password_hash
}

// HTTP request utilities
export const makeSignupRequest = async (username: string, password: string): Promise<TestApiResponse> => {
  const response = await fetch(`${TEST_BASE_URL}/signup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  })
  return {
    status: response.status,
    data: await response.json() as ApiResponse,
    response
  }
}

export const makeLoginRequest = async (username: string, password: string): Promise<TestApiResponse> => {
  const response = await fetch(`${TEST_BASE_URL}/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password })
  })
  return {
    status: response.status,
    data: await response.json() as ApiResponse,
    response
  }
}

// Test data generators
export const generateValidUserData = () => ({
  username: `testuser_${Date.now()}_${Math.random().toString(36).slice(2, 11)}`,
  password: `testpass_${Date.now()}`
})

export const generateInvalidUserData = () => ({
  username: 'ab', // too short
  password: '123' // too short
})

// Cleanup utilities
export const resetTestDatabase = () => {
  try {
    cleanUsersTable()
  } catch (error) {
    console.log('Error resetting test database:', error)
  }
}

// Test assertion helpers
export const expectSuccessResponse = (result: TestApiResponse, expectedMessage?: string) => {
  expect(result.status).toBe(201) // or 200 for login
  expect(result.data.success).toBe(true)
  if (expectedMessage) {
    expect(result.data.message).toBe(expectedMessage)
  }
}

export const expectErrorResponse = (result: TestApiResponse, expectedStatus: number, expectedMessage?: string) => {
  expect(result.status).toBe(expectedStatus)
  expect(result.data.success).toBe(false)
  if (expectedMessage) {
    expect(result.data.message).toBe(expectedMessage)
  }
}