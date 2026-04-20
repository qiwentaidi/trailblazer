# Trailblazer Admin

Trailblazer Admin is the new React-based frontend for the Trailblazer scanning platform. It replaces the previous Vue template with a Umi + Ant Design shell focused on the core operator flow: login, task center, task detail, and configuration management.

## Tech Stack

- Umi 4
- Ant Design 6
- React 19
- TypeScript
- Zustand
- `umi-request`

## Local Development

Install dependencies:

```bash
corepack pnpm install
```

Start the development server:

```bash
corepack pnpm dev
```

If the backend is running on a non-default local port, append `?backend_port=<port>` to the frontend URL.

Example:

```text
http://localhost:8000/?backend_port=9092
```

## Build

Run a local type check:

```bash
corepack pnpm typecheck
```

Build the production bundle:

```bash
corepack pnpm build
```

## Current Scope

This frontend currently covers:

- login and auth bootstrap
- task center list
- task detail with overview, site tree, risks, and assets
- settings for AI config, vulnerability rules, and Elasticsearch health

## Backend Integration

The frontend expects the Trailblazer backend API to expose:

- `POST /api/auth/login`
- `GET /api/user/info`
- `GET /api/task/records`
- `GET /api/task/:taskId/tree`
- `GET /api/task/:taskId/vulns`
- `GET /api/task/:taskId/assets`
- `GET /api/config`
- `POST /api/config`
- `GET /api/health/es`

## Notes

- Session state is stored in browser local storage.
- Task detail uses background polling for risk refresh.
- Settings save is disabled until the initial config load succeeds.
