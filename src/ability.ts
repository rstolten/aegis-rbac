import { type AbilityTuple, type MongoAbility, createMongoAbility } from "@casl/ability";
import { parsePermission } from "./permission";
import type { RBACConfig } from "./types";

/**
 * Collect all permissions for a role, including inherited permissions from hierarchy.
 */
function collectPermissions<TRole extends string>(
	config: RBACConfig<TRole>,
	role: TRole,
): string[] {
	const roleConfig = config.roles[role];
	if (!roleConfig) return [];

	const permissions = [...roleConfig.permissions];

	if (config.hierarchy) {
		const roleIndex = config.hierarchy.indexOf(role);
		if (roleIndex !== -1) {
			// Inherit permissions from all roles below in the hierarchy
			for (let i = roleIndex + 1; i < config.hierarchy.length; i++) {
				const lowerRole = config.hierarchy[i];
				const lowerConfig = config.roles[lowerRole];
				if (lowerConfig) {
					permissions.push(...lowerConfig.permissions);
				}
			}
		}
	}

	return permissions;
}

/**
 * Build a CASL ability for a given role based on the RBAC config.
 *
 * @example
 * ```ts
 * const ability = buildAbility(config, "admin");
 * ability.can("update", "workspace"); // true
 * ability.can("delete", "workspace"); // false
 * ```
 */
export function buildAbility<TRole extends string>(
	config: RBACConfig<TRole>,
	role: TRole,
): MongoAbility<AbilityTuple> {
	// Super admin gets full access
	if (config.superAdmin && role === config.superAdmin) {
		return createMongoAbility([{ action: "manage", subject: "all" }]);
	}

	const permissions = collectPermissions(config, role);
	const rules = permissions.map((p) => {
		const { action, subject } = parsePermission(p);
		return { action, subject };
	});

	return createMongoAbility(rules);
}
