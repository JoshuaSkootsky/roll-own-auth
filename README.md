# roll-own-auth

Roll your own auth

(1) Use bcrypt library hash and compare passwords
(2) Use Zod for run time validation
(3) Tests demonstrate how to use it and test it
(4) Issue sessions 
(5) Do app based salt and pepper for the bcrypt hashing


v1 is minimal
v2 has app level salt and pepper, and sessions/secure cookies.

This is all simple/example minimal.

## Getting Started

To install dependencies:

```bash
bun install
```

To run:

```bash
bun run index.ts
```

This project was created using `bun init` in bun v1.2.19. [Bun](https://bun.com) is a fast all-in-one JavaScript runtime.

### Actually getting started

Install bun!

`curl -fsSL https://bun.sh/install | bash`


### SQL Lite

You can just write a schema for SQL Lite! It's great. See `schema.sql`

### Server

`server.ts` is a simple server with Bun.


