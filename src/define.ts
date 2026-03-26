import type { RBACConfig, RoleConfig } from "./types";

/**
 * Validate a permission string format.
 * Valid: "*", "resource", "resource:action", "resource:*"
 * Invalid: "", ":", ":read", "brands:", "a:b:c", "*:read", "*:*"
 */
function isValidPermission(permission: string): boolean {
	if (permission === "*") return true;
	if (permission.length === 0) return false;
	if (permission.startsWith(":") || permission.endsWith(":")) return false;
	const parts = permission.split(":");
	if (parts.length > 2) return false;
	if (!parts.every((p) => p.length > 0)) return false;
	// Subject (resource) cannot be "*" — use standalone "*" for global wildcard
	if (parts[0] === "*") return false;
	return true;
}

/**
 * Recursively freeze an object and all nested objects/arrays.
 */
function deepFreeze<T extends object>(obj: T): T {
	Object.freeze(obj);
	for (const value of Object.values(obj)) {
		if (value !== null && typeof value === "object" && !Object.isFrozen(value)) {
			deepFreeze(value);
		}
	}
	return obj;
}

/**
 * Define roles and permissions for a project.
 * Returns a deeply frozen config object used by buildAbility() and middleware.
 * Validates config structure and throws on invalid input.
 *
 * @example
 * ```ts
 * const config = defineRoles({
 *   roles: {
 *     owner: { permissions: ["*"] },
 *     admin: { permissions: ["workspace:update", "members:*"] },
 *     viewer: { permissions: ["workspace:read", "analytics:read"] },
 *   },
 *   hierarchy: ["owner", "admin", "viewer"],
 *   superAdmin: "owner",
 * });
 * ```
 */
export function defineRoles<TRole extends string>(
	config: RBACConfig<TRole> & { roles: Record<TRole, RoleConfig> },
): Readonly<RBACConfig<TRole>> {
	const roleNames = Object.keys(config.roles) as TRole[];

	if (roleNames.length === 0) {
		throw new Error("RBAC config must define at least one role");
	}

	// Validate permissions format
	for (const role of roleNames) {
		const roleConfig = config.roles[role];
		for (const permission of roleConfig.permissions) {
			if (!isValidPermission(permission)) {
				throw new Error(
					`Invalid permission "${permission}" in role "${role}". Use "resource:action", "resource:*", or "*"`,
				);
			}
		}
	}

	// Validate hierarchy references existing roles
	if (config.hierarchy) {
		for (const role of config.hierarchy) {
			if (!config.roles[role]) {
				throw new Error(`Hierarchy references unknown role "${role}"`);
			}
		}
	}

	// Validate superAdmin references existing role
	if (config.superAdmin && !config.roles[config.superAdmin]) {
		throw new Error(`superAdmin references unknown role "${config.superAdmin}"`);
	}

	return deepFreeze(config);
}
