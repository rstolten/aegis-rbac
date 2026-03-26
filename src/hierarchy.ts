import type { RBACConfig } from "./types";

/**
 * Check if a user's role is at or above a required role in the hierarchy.
 * Lower index = higher rank. Returns false if either role is not in the hierarchy.
 *
 * @example
 * ```ts
 * // hierarchy: ["owner", "admin", "viewer"]
 * isRoleAtOrAbove(config, "owner", "admin");  // true (owner >= admin)
 * isRoleAtOrAbove(config, "viewer", "admin"); // false (viewer < admin)
 * isRoleAtOrAbove(config, "admin", "admin");  // true (equal)
 * ```
 */
export function isRoleAtOrAbove<TRole extends string>(
	config: RBACConfig<TRole>,
	userRole: TRole,
	requiredRole: TRole,
): boolean {
	if (!config.hierarchy) return false;
	const userIndex = config.hierarchy.indexOf(userRole);
	const requiredIndex = config.hierarchy.indexOf(requiredRole);
	if (userIndex === -1 || requiredIndex === -1) return false;
	// Lower index = higher rank
	return userIndex <= requiredIndex;
}
