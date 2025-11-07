# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

NaviHive is a modern website navigation management system built as a full-stack application deployed on Cloudflare Workers. It combines a React 19 frontend with a Cloudflare Workers backend using D1 (SQLite) database.

## Development Commands

### Essential Commands
```bash
# Install dependencies
pnpm install

# Start development server (runs Vite + Cloudflare Workers locally)
pnpm dev

# Build the project
pnpm build

# Preview production build locally
pnpm preview

# Deploy to Cloudflare Workers
pnpm deploy

# Linting and formatting
pnpm lint
pnpm format
pnpm format:check

# Security: Generate password hash for authentication
pnpm hash-password <your-password>

# Generate Cloudflare Workers types
pnpm cf-typegen
```

### Wrangler CLI Commands
```bash
# Login to Cloudflare
wrangler login

# Create D1 database
wrangler d1 create navigation-db

# Execute SQL on D1 database
wrangler d1 execute navigation-db --file=schema.sql

# Export D1 database
wrangler d1 export navigation-db

# View logs
wrangler tail
```

## Architecture

### Frontend Architecture
- **Framework**: React 19 with TypeScript
- **UI Library**: Material UI 7.0 with emotion styling
- **Styling**: Tailwind CSS 4.1 + CSS-in-JS (emotion)
- **Drag & Drop**: DND Kit for sortable groups and sites
- **Build Tool**: Vite 6 with Cloudflare plugin
- **API Layer**: Client abstraction in `src/API/` with mock support for development

### Backend Architecture
- **Runtime**: Cloudflare Workers (serverless)
- **Database**: Cloudflare D1 (SQLite)
- **Authentication**: JWT-based auth using @cfworker/jwt
- **Entry Point**: `worker/index.ts` handles all API routes

### Key Design Patterns

1. **API Route Structure**: All API routes are prefixed with `/api/` and handled in `worker/index.ts`
   - Authentication middleware checks JWT tokens for protected routes
   - Input validation functions prevent malformed data
   - Routes for: groups, sites, configs, login, export/import

2. **Client Architecture**: Two API implementations
   - `NavigationClient` (src/API/client.ts) - Real HTTP client
   - `MockNavigationClient` (src/API/mock.ts) - In-memory mock for dev
   - Selected via environment variables (`VITE_USE_REAL_API`)

3. **State Management**: Component-level state with React hooks
   - No global state library (Redux, Zustand, etc.)
   - API responses cached in component state
   - Drag-and-drop state managed by DND Kit

4. **Database Schema**: Three main tables
   - `groups`: Navigation categories with ordering
   - `sites`: Website links associated with groups
   - `configs`: Key-value store for site settings (title, name, custom CSS)

## Configuration

### Environment Variables (wrangler.jsonc)
```jsonc
{
  "vars": {
    "AUTH_ENABLED": "true",    // Enable/disable authentication
    "AUTH_USERNAME": "admin",   // Admin username
    "AUTH_PASSWORD": "$2a$10$...", // Admin password bcrypt hash (generate with: pnpm hash-password yourPassword)
    "AUTH_SECRET": "secret-key"  // JWT signing key (use strong random value)
  },
  "d1_databases": [{
    "binding": "DB",
    "database_name": "navigation-db",
    "database_id": "your-database-id"
  }]
}
```

**Password Security**: Use `pnpm hash-password <password>` to generate bcrypt hashes for AUTH_PASSWORD.

### Frontend Environment Variables
- `VITE_USE_REAL_API`: Set to "true" to use real API in development (default: use mock)

## Database Initialization

The database must be initialized after deployment. Run SQL in Cloudflare D1 console:

```sql
-- Create groups table
CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    order_num INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create sites table
CREATE TABLE IF NOT EXISTS sites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    url TEXT NOT NULL,
    icon TEXT,
    description TEXT,
    notes TEXT,
    order_num INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
);

-- Create configs table
CREATE TABLE IF NOT EXISTS configs (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Mark as initialized
INSERT INTO configs (key, value) VALUES ('DB_INITIALIZED', 'true');
```

## Key Code Locations

### Backend (Cloudflare Workers)
- `worker/index.ts` - Main worker entry point with all API routes
- `src/API/http.ts` - NavigationAPI class with database operations

### Frontend Components
- `src/App.tsx` - Main application with layout and state management
- `src/components/GroupCard.tsx` - Display group with sites
- `src/components/SiteCard.tsx` - Individual site display
- `src/components/LoginForm.tsx` - Authentication UI
- `src/components/SortableGroupItem.tsx` - Drag-and-drop wrapper for groups
- `src/components/SiteSettingsModal.tsx` - Global settings dialog
- `src/components/ThemeToggle.tsx` - Dark/light mode toggle

### API Layer
- `src/API/client.ts` - HTTP client implementation
- `src/API/mock.ts` - Mock client for development
- `src/API/http.ts` - Shared types and server-side API class

## Important Implementation Details

### Authentication Flow
1. User submits credentials via LoginForm
2. Worker validates against AUTH_USERNAME/AUTH_PASSWORD
3. On success, JWT token generated with configurable expiry (7 days or 30 days if "remember me" checked)
4. Token stored in localStorage
5. All subsequent API requests include `Authorization: Bearer <token>` header
6. Worker middleware validates token before processing protected routes

### Drag-and-Drop Ordering
1. User clicks "编辑排序" (Edit Sort) button
2. App enters sort mode (GroupSort or SiteSort)
3. DND Kit provides sortable interface
4. On save, batch updates sent to `/api/group-orders` or `/api/site-orders`
5. Backend updates `order_num` field for all affected items

### Data Export/Import
- Export: Serializes all groups, sites, and configs to JSON with version/timestamp
- Import:
  - Merges groups by name (creates if new, uses existing if found)
  - Sites matched by URL within same group (updates if found, creates if new)
  - Configs completely replaced by imported values

### Custom Styling
- Configs table stores `CUSTOM_CSS` key
- CSS injected into `<style>` tag in document head
- Allows users to override default styles without code changes

## Code Style

### Prettier Configuration
- Print width: 100 characters
- Indentation: 2 spaces
- Single quotes (including JSX)
- Semicolons required
- Trailing commas in ES5 style
- Arrow function parens: always

Format code before committing:
```bash
pnpm format
```

## Testing Considerations

- No test suite currently exists
- When adding tests, structure them by layer (unit tests for API, integration for components)
- Consider testing Worker routes with Miniflare (Cloudflare Workers simulator)
- Mock D1 database for unit tests

## Security Notes

1. **Input Validation**: All user inputs validated in worker/index.ts before database operations
2. **SQL Injection**: Protected via D1 prepared statements (never string concatenation)
3. **XSS**: React escapes outputs by default; be cautious with dangerouslySetInnerHTML
4. **Authentication**: JWT tokens expire; AUTH_SECRET should be cryptographically random in production
5. **CORS**: Not configured; same-origin only (appropriate for Workers with Assets)

## Deployment Workflow

1. Update code locally
2. Test with `pnpm dev`
3. Build with `pnpm build`
4. Deploy with `pnpm deploy` (runs build automatically)
5. Cloudflare Workers deploys globally within seconds
6. Database migrations must be run manually via Cloudflare dashboard

## Troubleshooting

### Build Issues
- Ensure all dependencies installed: `pnpm install`
- Check TypeScript compilation: `tsc -b`
- Verify wrangler.jsonc is valid JSON with comments

### Database Issues
- Check D1 binding name matches "DB" in wrangler.jsonc
- Verify database_id is correct
- Ensure database initialized (check configs table for DB_INITIALIZED)

### Authentication Issues
- Verify AUTH_ENABLED, AUTH_USERNAME, AUTH_PASSWORD set in wrangler.jsonc
- Check token in localStorage (key: "authToken")
- Tokens expire after 7 days (30 days with remember me)

### Development Mode
- By default, uses MockNavigationClient to avoid needing D1 in dev
- Set `VITE_USE_REAL_API=true` in .env to use real backend locally
- Requires `pnpm dev` to start local Cloudflare Workers server
