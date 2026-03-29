import {
	analyzePermission,
	collectConditionalPermissions,
	collectFieldPermissions,
	collectPermissions,
} from "./ability";
import { isRoleAtOrAbove } from "./hierarchy";
import { parsePermission } from "./permission";
import type { RBACConfig } from "./types";

/** A single debug trace entry explaining a permission decision */
export interface DebugTrace {
	permission: string;
	allowed: boolean;
	reason: string;
}

/** Full debug result for a permission check */
export interface DebugResult {
	role: string;
	permission: string;
	allowed: boolean;
	traces: DebugTrace[];
	effectivePermissions: string[];
	conditionalPermissions: Array<{ permission: string; conditions: Record<string, unknown> }>;
	fieldPermissions: Array<{ permission: string; fields: string[] }>;
}

/** Full debug result for a role check */
export interface DebugRoleResult {
	userRole: string;
	requiredRoles: string[];
	allowed: boolean;
	reason: string;
}

/**
 * Debug why a permission check passed or failed.
 * Returns a detailed trace of the decision process, including conditional and field rules.
 *
 * @example
 * ```ts
 * const result = debugCan(config, "viewer", "brands:write");
 * // {
 * //   role: "viewer",
 * //   permission: "brands:write",
 * //   allowed: false,
 * //   traces: [{ allowed: false, reason: '...' }],
 * //   effectivePermissions: ["workspace:read", "brands:read"],
 * //   conditionalPermissions: [],
 * //   fieldPermissions: []
 * // }
 * ```
 */
export function debugCan<TRole extends string>(
	config: RBACConfig<TRole>,
	role: TRole,
	permission: string,
): DebugResult {
	const traces: DebugTrace[] = [];
	const effectivePermissions = [...new Set(collectPermissions(config, role))];
	const conditionalPermissions = collectConditionalPermissions(config, role).map((cp) => ({
		permission: cp.permission,
		conditions: cp.conditions,
	}));
	const fieldPermissions = collectFieldPermissions(config, role).map((fp) => ({
		permission: fp.permission,
		fields: fp.fields,
	}));

	const result = {
		role,
		permission,
		allowed: false,
		traces,
		effectivePermissions,
		conditionalPermissions,
		fieldPermissions,
	};

	// Super admin bypass
	const analysis = analyzePermission(config, role, permission);
	if (analysis.isSuperAdmin) {
		traces.push({
			permission,
			allowed: true,
			reason: `Role "${role}" is superAdmin — bypasses all checks`,
		});
		return { ...result, allowed: true, effectivePermissions: ["*"] };
	}

	const roleConfig = config.roles[role];
	const { subject } = parsePermission(permission);
	if (analysis.deniedBy) {
		traces.push({
			permission,
			allowed: false,
			reason: `Denied by explicit deny rule "${analysis.deniedBy}" on role "${role}"`,
		});
		return result;
	}

	// Check direct permissions
	if (analysis.grantedBy) {
		const parsed = parsePermission(analysis.grantedBy);
		if (analysis.grantedBy === "*") {
			traces.push({
				permission,
				allowed: true,
				reason: 'Granted by wildcard "*" permission',
			});
			return { ...result, allowed: true };
		}
		if (parsed.action === "manage" && parsed.subject === subject) {
			traces.push({
				permission,
				allowed: true,
				reason: `Granted by resource wildcard "${analysis.grantedBy}"`,
			});
			return { ...result, allowed: true };
		}
		const isOwn = roleConfig?.permissions.includes(analysis.grantedBy);
		traces.push({
			permission,
			allowed: true,
			reason: isOwn
				? `Granted by direct permission "${analysis.grantedBy}" on role "${role}"`
				: `Granted by inherited permission "${analysis.grantedBy}"`,
		});
		return { ...result, allowed: true };
	}

	if (analysis.conditionalMatches.length > 0) {
		traces.push({
			permission,
			allowed: false,
			reason: `Matched conditional rule "${analysis.conditionalMatches[0].permission}", but this API cannot authorize without a concrete resource instance.`,
		});
		return result;
	}

	if (analysis.fieldMatches.length > 0) {
		traces.push({
			permission,
			allowed: false,
			reason: `Matched field-level rule "${analysis.fieldMatches[0].permission}", but this API cannot authorize field-scoped access from a permission string alone.`,
		});
		return result;
	}

	// Not found
	traces.push({
		permission,
		allowed: false,
		reason: `Role "${role}" does not have "${permission}" or a covering wildcard`,
	});

	return result;
}

/**
 * Debug why a role check passed or failed.
 *
 * @example
 * ```ts
 * const result = debugRole(config, "viewer", "admin");
 * // {
 * //   userRole: "viewer",
 * //   requiredRoles: ["admin"],
 * //   allowed: false,
 * //   reason: 'Denied: "viewer" is below "admin" in hierarchy'
 * // }
 * ```
 */
export function debugRole<TRole extends string>(
	config: RBACConfig<TRole>,
	userRole: TRole,
	...requiredRoles: TRole[]
): DebugRoleResult {
	// Direct match
	if (requiredRoles.includes(userRole)) {
		return {
			userRole,
			requiredRoles,
			allowed: true,
			reason: `Direct role match: "${userRole}"`,
		};
	}

	// Hierarchy check
	if (config.hierarchy) {
		for (const required of requiredRoles) {
			if (isRoleAtOrAbove(config, userRole, required)) {
				return {
					userRole,
					requiredRoles,
					allowed: true,
					reason: `Role "${userRole}" is at or above "${required}" in hierarchy`,
				};
			}
		}
	}

	// Super admin bypass
	if (config.superAdmin && userRole === config.superAdmin) {
		return {
			userRole,
			requiredRoles,
			allowed: true,
			reason: `Role "${userRole}" is superAdmin — bypasses role checks`,
		};
	}

	// Denied
	const reasons: string[] = [];
	if (!config.hierarchy) {
		reasons.push("no hierarchy defined");
	} else {
		for (const required of requiredRoles) {
			reasons.push(`"${userRole}" is below "${required}" in hierarchy`);
		}
	}

	return {
		userRole,
		requiredRoles,
		allowed: false,
		reason: `Denied: ${reasons.join("; ")}`,
	};
}
