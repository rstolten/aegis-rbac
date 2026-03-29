import {
	analyzePermission,
	collectConditionalPermissions,
	collectFieldPermissions,
	collectPermissions,
} from "./ability";
import { parsePermission } from "./permission";
import type { RBACConfig } from "./types";

/**
 * Check if a role has an unconditional permission.
 * Conditional and field-scoped rules require a concrete resource instance
 * and are therefore not treated as granted by this string-based helper.
 * Use buildAbility() for conditional/field-scoped checks.
 *
 * @example
 * ```ts
 * can(config, "admin", "members:invite"); // true
 * can(config, "viewer", "members:invite"); // false
 * ```
 */
export function can<TRole extends string>(
	config: RBACConfig<TRole>,
	role: TRole,
	permission: string,
): boolean {
	return analyzePermission(config, role, permission).allowed;
}

/**
 * Assert that a role has an unconditional permission. Throws if unauthorized.
 * Conditional and field-scoped rules require a concrete resource instance.
 * Use buildAbility() for conditional/field-scoped checks.
 *
 * @example
 * ```ts
 * authorize(config, "viewer", "members:invite");
 * // throws: Forbidden: role "viewer" cannot "invite" on "members"
 * ```
 */
export function authorize<TRole extends string>(
	config: RBACConfig<TRole>,
	role: TRole,
	permission: string,
): void {
	if (!can(config, role, permission)) {
		const { action, subject } = parsePermission(permission);
		throw new Error(`Forbidden: role "${role}" cannot "${action}" on "${subject}"`);
	}
}

/** Full permissions summary for a role */
export interface PermissionsSummary {
	/** Standard permissions (deduplicated, including inherited) */
	permissions: string[];
	/** Conditional permissions with their conditions */
	conditionals: Array<{ permission: string; conditions: Record<string, unknown> }>;
	/** Field-level permissions */
	fields: Array<{ permission: string; fields: string[] }>;
	/** Denied permissions */
	denied: string[];
}

/**
 * Get all effective permissions for a role, including conditionals, fields, and denials.
 * Useful for debugging, admin UIs, and displaying "what can this role do?".
 *
 * @example
 * ```ts
 * getPermissions(config, "editor");
 * // {
 * //   permissions: ["posts:read"],
 * //   conditionals: [{ permission: "posts:update", conditions: { authorId: "{{userId}}" } }],
 * //   fields: [],
 * //   denied: []
 * // }
 * ```
 */
export function getPermissions<TRole extends string>(
	config: RBACConfig<TRole>,
	role: TRole,
): PermissionsSummary {
	if (!(role in config.roles)) {
		throw new Error(`Unknown role "${role}". Valid roles: ${Object.keys(config.roles).join(", ")}`);
	}

	if (config.superAdmin && role === config.superAdmin) {
		return { permissions: ["*"], conditionals: [], fields: [], denied: [] };
	}

	const permissions = [...new Set(collectPermissions(config, role))];

	const conditionals = collectConditionalPermissions(config, role).map((cp) => ({
		permission: cp.permission,
		conditions: cp.conditions,
	}));

	const fields = collectFieldPermissions(config, role).map((fp) => ({
		permission: fp.permission,
		fields: fp.fields,
	}));

	const roleConfig = config.roles[role];
	const denied = roleConfig?.deny ? [...roleConfig.deny] : [];

	return { permissions, conditionals, fields, denied };
}
