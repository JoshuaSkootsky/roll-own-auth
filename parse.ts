import { z } from 'zod';

// Auth schema
const AuthSchema = z.object({
  username: z.string().min(3, 'Username must be at least 3 characters'),
  password: z.string().min(6, 'Password must be at least 6 characters'),
});

// TypeScript inference
type AuthData = z.infer<typeof AuthSchema>;

// AuthBody parses the request body and returns a SignUpData object
export const AuthBody = async (req: Request) => {
    const body = await req.json();
    return AuthSchema.safeParse(body);
};

