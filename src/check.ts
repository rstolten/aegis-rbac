import { buildAbility } from "./ability";
import { parsePermission } from "./permission";
import type { RBACConfig } from "./types";

/**
 * Check if a role has a specific permission.
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
	const ability = buildAbility(config, role);
	const { action, subject } = parsePermission(permission);
	return ability.can(action, subject);
}

/**
 * Assert that a role has a specific permission. Throws if unauthorized.
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
