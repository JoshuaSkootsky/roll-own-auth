import { beforeAll, afterAll } from 'bun:test'
import { Database } from 'bun:sqlite'

// Modular test configuration
// Priority: TEST_PORT env var > PORT env var > 5050 fallback
const getTestPort = (): number => {
  return Number(process.env.TEST_PORT) || 
         Number(process.env.PORT) || 
         5050
}

export const TEST_PORT = getTestPort()
export const TEST_DB_PATH = './test_db.sqlite'
export const TEST_BASE_URL = `http://localhost:${TEST_PORT}`

// Test environment variables for JWT
export const TEST_JWT_SECRET = 'test-jwt-secret-key-for-testing-only'
export const TEST_PEPPERS = ['test-pepper-string-for-testing-only']

// IMPORTANT: Set environment variables at module load time
// This ensures they're available when test-server-helpers.ts is imported
process.env.PEPPERS = TEST_PEPPERS.join(',')
process.env.JWT_SECRET = TEST_JWT_SECRET

// Export function for other test files to use
export const getTestPortConfig = () => ({
  port: TEST_PORT,
  dbPath: TEST_DB_PATH,
  baseUrl: TEST_BASE_URL
})

// Global test server instance
let testServer: any = null

// Setup test environment before all tests
beforeAll(async () => {
  console.log('🧪 Setting up test environment...')
  
  // Note: Environment variables are now set at module load time (above)
  
  // Remove existing test database if it exists
  try {
    const fs = await import('fs')
    if (fs.existsSync(TEST_DB_PATH)) {
      fs.rmSync(TEST_DB_PATH)
      console.log('🗑️  Removed existing test database')
    }
  } catch (error) {
    console.log('No existing test database to remove')
  }
  
  // Create fresh test database with schema
  const testDb = new Database(TEST_DB_PATH)
  const schema = await Bun.file('schema.sql').text()
  testDb.run(schema)
  testDb.close()
  console.log('📊 Created fresh test database')
  
  // Start test server on port 5050
  console.log('🚀 Starting test server on port', TEST_PORT)
  
  // Import server functionality and start test server
  const { createTestServer } = await import('./test-helpers')
  const testServerInstance = createTestServer(Number(TEST_PORT), TEST_DB_PATH)
  testServer = testServerInstance.server
  
  // Wait for server to be ready
  await new Promise(resolve => setTimeout(resolve, 100))
  console.log('✅ Test environment ready')
})

// Cleanup after all tests
afterAll(async () => {
  console.log('🧹 Cleaning up test environment...')
  
  // Stop test server
  if (testServer) {
    testServer.stop()
    console.log('🛑 Stopped test server')
  }
  
  // Remove test database
  try {
    const fs = await import('fs')
    if (fs.existsSync(TEST_DB_PATH)) {
      fs.rmSync(TEST_DB_PATH)
      console.log('🗑️  Removed test database')
    }
  } catch (error) {
    console.log('No test database to remove')
  }
  
  console.log('✅ Test environment cleaned up')
})