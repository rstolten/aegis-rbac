import type { Context, Next } from "hono";
import { createGuard } from "../guard";
import type { RBACConfig } from "../types";

/** Options for creating Hono RBAC middleware */
export interface HonoRBACOptions<TRole extends string = string> {
	/** The RBAC config to use for permission checks */
	config: RBACConfig<TRole>;
	/** Extract the user's role from the Hono context */
	getRole: (c: Context) => TRole | undefined;
	/** Custom handler for 401 Unauthorized. Defaults to JSON response. */
	onUnauthorized?: (c: Context) => Response | Promise<Response>;
	/** Custom handler for 403 Forbidden. Defaults to JSON response. */
	onForbidden?: (c: Context) => Response | Promise<Response>;
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
	const guard = createGuard(config);

	const handleUnauthorized =
		options.onUnauthorized ?? ((c: Context) => c.json({ data: null, error: "Unauthorized" }, 401));
	const handleForbidden =
		options.onForbidden ?? ((c: Context) => c.json({ data: null, error: "Forbidden" }, 403));

	/**
	 * Middleware that checks if the user has specific permissions.
	 * Permission format: "resource:action" (e.g., "brands:write", "members:invite")
	 * All permissions must pass (AND logic).
	 */
	function requirePermission(...permissions: string[]) {
		return async (c: Context, next: Next) => {
			const role = getRole(c);
			if (!role) {
				return handleUnauthorized(c);
			}

			const { allowed, ability } = guard.checkPermission(role, ...permissions);
			c.set("ability", ability);

			if (!allowed) {
				return handleForbidden(c);
			}

			await next();
		};
	}

	/**
	 * Middleware that checks if the user has one of the specified roles.
	 * Respects hierarchy — a higher role passes a check for a lower role.
	 * Simpler than permission checking — use when you just need role gating.
	 */
	function requireRole(...allowedRoles: TRole[]) {
		return async (c: Context, next: Next) => {
			const role = getRole(c);
			if (!role) {
				return handleUnauthorized(c);
			}

			const { allowed, ability } = guard.checkRole(role, ...allowedRoles);
			c.set("ability", ability);

			if (!allowed) {
				return handleForbidden(c);
			}

			await next();
		};
	}

	return { requirePermission, requireRole };
}
