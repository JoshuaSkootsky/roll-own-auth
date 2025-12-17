import { Database } from 'bun:sqlite'
import { hash, compare } from 'bcrypt'
import { sign, verify } from 'jsonwebtoken'
import type { SignOptions } from 'jsonwebtoken'

// Configuration types for dependency injection
export interface AuthConfig {
  salt: number
  jwtSecret: string
  jwtExpireTime: string
  peppers: string[]
}

// Result types
export interface AuthResult {
  success: boolean
  message: string
  token?: string
}

export interface AuthUser {
  id: number
  username: string
  password_hash: string
}

export interface AuthUserSafe {
  id: number
  username: string
}

export interface TokenPayload {
  username: string
  id: number
  iat: number
  exp: number
}

// Repository interface for data access
export interface UserRepository {
  create(username: string, passwordHash: string): Promise<void>
  findByUsername(username: string): AuthUser | undefined
  updatePasswordHash(userId: number, passwordHash: string): Promise<void>
}

// AuthService interface
export interface AuthService {
  signUp(username: string, password: string): Promise<AuthResult>
  login(username: string, password: string): Promise<AuthResult>
  findUser(username: string): AuthUser | undefined
  authenticateRequest(req: Request): { valid: boolean; user?: TokenPayload }
}

// UserRepository implementation
export class SqliteUserRepository implements UserRepository {
  constructor(private db: Database) {}

  create(username: string, passwordHash: string): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        this.db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run(
          username,
          passwordHash
        )
        resolve()
      } catch (error) {
        reject(error)
      }
    })
  }

  findByUsername(username: string): AuthUser | undefined {
    const result = this.db.prepare('SELECT * FROM users WHERE username = ?').get(username)
    return result ? result as AuthUser : undefined
  }

  updatePasswordHash(userId: number, passwordHash: string): Promise<void> {
    return new Promise((resolve, reject) => {
      try {
        this.db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(passwordHash, userId)
        resolve()
      } catch (error) {
        reject(error)
      }
    })
  }
}

// AuthService implementation
export class BcryptAuthService implements AuthService {
  constructor(
    private userRepo: UserRepository,
    private config: AuthConfig
  ) {}

  async signUp(username: string, password: string): Promise<AuthResult> {
    const hashedPassword = await this.hashPassword(password)
    
    try {
      await this.userRepo.create(username, hashedPassword)
      return { success: true, message: 'User created.' }
    } catch (error) {
      return { success: false, message: 'Username already exists.' }
    }
  }

  async login(username: string, password: string): Promise<AuthResult> {
    const user = this.userRepo.findByUsername(username)

    if (!user) {
      return { success: false, message: 'User not found.' }
    }

    const { isValid, usedPepper } = await this.verifyPassword(password, user.password_hash)
    if (!isValid) {
      return { success: false, message: 'Invalid password.' }
    }

    // Pepper rotation: upgrade to latest pepper if needed
    if (usedPepper !== this.config.peppers[0]) {
      const newPasswordHash = await this.hashPassword(password)
      await this.userRepo.updatePasswordHash(user.id, newPasswordHash)
    }

    const token = sign(
      { username: user.username, id: user.id },
      this.config.jwtSecret,
      { expiresIn: this.config.jwtExpireTime } as any
    )

    return { success: true, message: 'Login successful.', token }
  }

  findUser(username: string): AuthUser | undefined {
    return this.userRepo.findByUsername(username)
  }

  authenticateRequest(req: Request): { valid: boolean; user?: TokenPayload } {
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
      const decoded = verify(token, this.config.jwtSecret) as TokenPayload
      return { valid: true, user: decoded }
    } catch (err) {
      return { valid: false }
    }
  }

  // Private helper methods
  private async hashPassword(password: string): Promise<string> {
    return hash(this.config.peppers[0] + password, this.config.salt)
  }

  private async verifyPassword(
    password: string,
    hash: string
  ): Promise<{ isValid: boolean; usedPepper: string | null }> {
    if (!hash) {
      return { isValid: false, usedPepper: null }
    }

    for (const pepper of this.config.peppers) {
      const isValid = await compare(pepper + password, hash)
      if (isValid) {
        return { isValid: true, usedPepper: pepper }
      }
    }
    return { isValid: false, usedPepper: null }
  }
}

// Factory function for creating AuthService instances
export function createAuthService(
  db: Database,
  config: AuthConfig
): AuthService {
  const userRepo = new SqliteUserRepository(db)
  return new BcryptAuthService(userRepo, config)
}