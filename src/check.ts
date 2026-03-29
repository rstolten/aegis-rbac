import {
	analyzePermission,
	collectConditionalPermissions,
	collectFieldPermissions,
	collectPermissions,
} from "./ability";
import { parsePermission } from "./permission";
import type { AbilityContext, RBACConfig } from "./types";

/**
 * Check if a role has an unconditional permission.
 * Conditional and field-scoped rules require a concrete resource instance
 * and are therefore not treated as granted by this string-based helper.
 *
 * @example
 * ```ts
 * can(config, "admin", "members:invite"); // true
 * can(config, "viewer", "members:invite"); // false
 *
 * // Conditional permissions require buildAbility() + a concrete subject instance
 * can(config, "editor", "posts:update", { userId: "user-123" }); // false
 * ```
 */
export function can<TRole extends string>(
	config: RBACConfig<TRole>,
	role: TRole,
	permission: string,
	_context?: AbilityContext,
): boolean {
	return analyzePermission(config, role, permission).allowed;
}

/**
 * Assert that a role has an unconditional permission. Throws if unauthorized.
 * Conditional and field-scoped rules require a concrete resource instance.
 *
 * @example
 * ```ts
 * authorize(config, "viewer", "members:invite");
 * // throws: Forbidden: role "viewer" cannot "invite" on "members"
 *
 * // Conditional permissions require buildAbility() + a concrete subject instance
 * authorize(config, "editor", "posts:update", { userId: "user-123" }); // throws
 * ```
 */
export function authorize<TRole extends string>(
	config: RBACConfig<TRole>,
	role: TRole,
	permission: string,
	context?: AbilityContext,
): void {
	if (!can(config, role, permission, context)) {
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
