# rbac

Config-driven RBAC engine built on [CASL](https://casl.js.org/). Define roles and permissions once, use everywhere.

## Install

This is an internal package. Add it as a workspace dependency or link it directly:

```bash
# In your project's package.json, add:
"rbac": "file:../rbac"

# Then install
bun install
```

## Quick start

### 1. Define roles

```ts
import { defineRoles } from "rbac";

export const rbacConfig = defineRoles({
  roles: {
    owner: { permissions: ["*"] },
    admin: {
      permissions: [
        "workspace:update",
        "members:invite",
        "members:remove",
        "brands:*",
      ],
    },
    viewer: {
      permissions: ["workspace:read", "brands:read"],
    },
  },
  hierarchy: ["owner", "admin", "viewer"],
  superAdmin: "owner",
});
```

### 2. Check permissions

```ts
import { can, authorize } from "rbac";

can(rbacConfig, "admin", "members:invite"); // true
can(rbacConfig, "viewer", "members:invite"); // false

// Throws if denied
authorize(rbacConfig, "viewer", "members:invite");
// Error: Forbidden: role "viewer" cannot "invite" on "members"
```

### 3. Hono middleware

```ts
import { createRBACMiddleware } from "rbac/middleware/hono";

const { requirePermission, requireRole } = createRBACMiddleware({
  config: rbacConfig,
  getRole: (c) => c.get("workspaceRole"),
});

app.get("/brands", requirePermission("brands:read"), handler);
app.post("/brands", requirePermission("brands:write"), handler);
app.delete("/workspace", requireRole("owner"), handler);

// Multiple permissions (all must pass)
app.get("/reports", requirePermission("brands:read", "analytics:read"), handler);
```

## Permission format

```
"*"              → full access (manage all)
"resource:*"     → full access to resource
"resource:action" → specific action on resource
"resource"       → shorthand for resource:* (manage)
```

## Hierarchy

Roles inherit all permissions from roles below them:

```ts
hierarchy: ["owner", "admin", "manager", "analyst"]
//          ↑ inherits from all below
//                  ↑ inherits from manager + analyst
//                           ↑ inherits from analyst
//                                       ↑ no inheritance
```

## Super admin

A role marked as `superAdmin` bypasses all permission and role checks:

```ts
defineRoles({
  roles: { ... },
  superAdmin: "owner", // owner can do everything
});
```

## Data scoping

For row-level filtering based on user relationships:

```ts
import { defineDataScope, resolveScope } from "rbac";

const scopes = defineDataScope({
  platform_admin: () => ({ type: "platform_admin" }),
  tenant_admin: (ctx) => ({ type: "tenant_admin", tenantId: ctx.tenantId }),
  staff: async (ctx) => ({
    type: "staff",
    groupIds: await getStaffGroups(ctx.userId),
  }),
});

const scope = await resolveScope(scopes, {
  userId: "user-123",
  tenantId: "tenant-456",
  role: "staff",
});
// { type: "staff", groupIds: ["group-1", "group-2"] }
```

## Validation

`defineRoles()` validates your config at startup:

- Permission format (`resource:action`, `resource:*`, `*`)
- Hierarchy roles must exist in `roles`
- `superAdmin` must exist in `roles`
- At least one role required

## API

| Export | Description |
|--------|-------------|
| `defineRoles(config)` | Define and validate RBAC config |
| `can(config, role, permission)` | Check permission (returns boolean) |
| `authorize(config, role, permission)` | Assert permission (throws on deny) |
| `buildAbility(config, role)` | Get CASL ability for advanced use |
| `parsePermission(permission)` | Parse permission string to action/subject |
| `defineDataScope(config)` | Define data scope resolvers |
| `resolveScope(config, ctx)` | Resolve scope for a user |
| `createRBACMiddleware(options)` | Create Hono middleware |

## Examples

See [`examples/`](./examples) for configs covering:

- **3-role workspace** — owner/editor/viewer
- **4-role workspace** — owner/admin/manager/analyst
- **Hierarchical with scoping** — platform_admin/tenant_admin/staff/member with row-level filtering

## License

MIT
