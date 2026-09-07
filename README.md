# @turystack/nestjs-oauth

Authorization Code + PKCE authorization server for NestJS. Issues the session as
httpOnly cookies, so no token ever reaches the page.

## Installation

```bash
pnpm add @turystack/nestjs-oauth
```

### Peer dependencies

The host application provides these:

```bash
pnpm add @nestjs/common @nestjs/core @turystack/nestjs-config @turystack/nestjs-iam @turystack/nestjs-server reflect-metadata zod
```

## Documentation

Options, API reference and examples:

**https://tury.dev/libs/nestjs-oauth**

## Development

```bash
pnpm install
pnpm typecheck
pnpm check
pnpm test
pnpm build
```
