import type { Context, Next } from "hono";
import { buildAbility } from "../ability";
import { parsePermission } from "../permission";
import type { RBACConfig } from "../types";

/** Options for creating Hono RBAC middleware */
export interface HonoRBACOptions<TRole extends string = string> {
	/** The RBAC config to use for permission checks */
	config: RBACConfig<TRole>;
	/** Extract the user's role from the Hono context */
	getRole: (c: Context) => TRole | undefined;
}

/**
 * Create Hono middleware for RBAC enforcement.
 *
 * @example
 * ```ts
 * const { requirePermission, requireRole } = createRBACMiddleware({
 *   config: rbacConfig,
 *   getRole: (c) => c.get("workspaceRole"),
 * });
 *
 * app.post("/brands", authMiddleware, requirePermission("brands:write"), handler);
 * app.delete("/workspace", authMiddleware, requireRole("owner"), handler);
 * ```
 */
export function createRBACMiddleware<TRole extends string>(options: HonoRBACOptions<TRole>) {
	const { config, getRole } = options;

	/**
	 * Middleware that checks if the user has a specific permission.
	 * Permission format: "resource:action" (e.g., "brands:write", "members:invite")
	 */
	function requirePermission(...permissions: string[]) {
		return async (c: Context, next: Next) => {
			const role = getRole(c);
			if (!role) {
				return c.json({ data: null, error: "Unauthorized" }, 401);
			}

			const ability = buildAbility(config, role);

			for (const permission of permissions) {
				const { action, subject } = parsePermission(permission);
				if (!ability.can(action, subject)) {
					return c.json({ data: null, error: "Forbidden" }, 403);
				}
			}

			await next();
		};
	}

	/**
	 * Middleware that checks if the user has one of the specified roles.
	 * Simpler than permission checking — use when you just need role gating.
	 */
	function requireRole(...allowedRoles: TRole[]) {
		return async (c: Context, next: Next) => {
			const role = getRole(c);
			if (!role) {
				return c.json({ data: null, error: "Unauthorized" }, 401);
			}

			// Direct role match
			if (allowedRoles.includes(role)) {
				await next();
				return;
			}

			// Super admin bypass
			if (config.superAdmin && role === config.superAdmin) {
				await next();
				return;
			}

			return c.json({ data: null, error: "Forbidden" }, 403);
		};
	}

	return { requirePermission, requireRole };
}
