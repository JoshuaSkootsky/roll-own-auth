# roll-own-auth

Roll your own auth

1. Use bcrypt library hash and compare passwords
2. Use Zod for run time validation of requests
3. Tests demonstrate how to use it and test it
4. Issue JWT tokens
5. Do app based salt and pepper for the bcrypt hashing, allow for multiple peppers and rotating peppers.

# Server Start
```sh
PORT=3000 PEPPERS=current-pepper,old-pepper,before-that-one bun run server.ts
```


# Installation instructions

To install

```bash
bun install
```


This project was created using `bun init` in bun v1.2.19. [Bun](https://bun.com) is a fast all-in-one JavaScript runtime.

### Installing Bun

Install bun!

`curl -fsSL https://bun.sh/install | bash`


### SQL Lite

You can just write a schema for SQL Lite! It's great. See `schema.sql`. A file called `db.sqlite` will be created in the root directory. We use SQL Lite as included in Bun.

# Dependency Injection

This project evolved to attach an auth service to the server. The auth service is exported for testing, and injected into the server in production.


