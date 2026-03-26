/**
 * Validate a permission string format.
 * Valid: "*", "resource", "resource:action", "resource:*"
 * Invalid: "", ":", ":read", "brands:", "a:b:c", "*:read", "*:*"
 */
export function isValidPermission(permission: string): boolean {
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
