import type { AuthService } from './auth-service'
import { AuthBody } from '../parse'

export interface ServerConfig {
  port: number
}

export interface ServerInstance {
  server: any
  stop: () => void
  authService: AuthService
}

export function createServer(authService: AuthService, config: ServerConfig): ServerInstance {
  const { port } = config

  // Create Bun server with injected dependencies
  const server = Bun.serve({
    port,
    fetch: async (req, res) => {
      // Log incoming requests
      console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`)
      const url = new URL(req.url)
      const path = url.pathname
      const method = req.method

      // signup route
      if (path === '/signup' && method === 'POST') {
        let parsed
        try {
          parsed = await AuthBody(req)
        } catch (error) {
          return new Response(JSON.stringify({ 
            success: false, 
            message: 'Invalid request format' 
          }), {
            headers: { 'Content-Type': 'application/json' },
            status: 400,
          })
        }
        
        if (!parsed.success) {
          return new Response(JSON.stringify({ 
            success: false, 
            message: parsed.error.issues?.map((i: any) => i.message).join(', ') || 'Validation error' 
          }), {
            headers: { 'Content-Type': 'application/json' },
            status: 400,
          })
        }

        const { username, password } = parsed.data
        const result = await authService.signUp(username, password)

        return new Response(JSON.stringify(result), {
          headers: { 'Content-Type': 'application/json' },
          status: result.success ? 201 : 400,
        })
      }

      // login route
      if (path === '/login' && method === 'POST') {
        let parsed
        try {
          parsed = await AuthBody(req)
        } catch (error) {
          return new Response(JSON.stringify({ 
            success: false, 
            message: 'Invalid request format' 
          }), {
            headers: { 'Content-Type': 'application/json' },
            status: 400,
          })
        }
        
        if (!parsed.success) {
          return new Response(JSON.stringify({ 
            success: false, 
            message: parsed.error.issues?.map((i: any) => i.message).join(', ') || 'Validation error' 
          }), {
            headers: { 'Content-Type': 'application/json' },
            status: 400,
          })
        }

        const { username, password } = parsed.data
        const result = await authService.login(username, password)

        return new Response(JSON.stringify(result), {
          headers: { 'Content-Type': 'application/json' },
          status: result.success ? 200 : 400,
        })
      }

      // 🔒 Protected route example
      if (path === '/profile' && method === 'GET') {
        const authResult = authService.authenticateRequest(req)
        if (!authResult.valid) {
          return new Response(
            JSON.stringify({ success: false, message: 'Unauthorized' }),
            { status: 401, headers: { 'Content-Type': 'application/json' } }
          )
        }
        return new Response(
          JSON.stringify({ success: true, message: `Hello, ${authResult.user!.username}!` }),
          { status: 200, headers: { 'Content-Type': 'application/json' } }
        )
      }

      // catch all
      return new Response('Use /signup, /login, or /profile', { status: 404 })
    },
  })

  console.log(`Server listening on port ${port}`)
  
  return {
    server,
    stop: () => server.stop(),
    authService
  }
}