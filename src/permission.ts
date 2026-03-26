import type { ParsedPermission } from "./types";
import { isValidPermission } from "./validate";

/**
 * Parse a permission string into action + subject.
 * Maps to CASL conventions: "*" → manage all, "resource:*" → manage resource.
 * Throws on malformed input.
 *
 * @example
 * ```ts
 * parsePermission("*")              // { action: "manage", subject: "all" }
 * parsePermission("brands:read")    // { action: "read", subject: "brands" }
 * parsePermission("brands:*")       // { action: "manage", subject: "brands" }
 * parsePermission("brands")         // { action: "manage", subject: "brands" }
 * ```
 */
export function parsePermission(permission: string): ParsedPermission {
	if (!isValidPermission(permission)) {
		throw new Error(
			`Invalid permission "${permission}". Use "resource:action", "resource:*", or "*"`,
		);
	}

	if (permission === "*") {
		return { action: "manage", subject: "all" };
	}

	const colonIndex = permission.indexOf(":");
	if (colonIndex === -1) {
		return { action: "manage", subject: permission };
	}

	const subject = permission.slice(0, colonIndex);
	const action = permission.slice(colonIndex + 1);

	if (action === "*") {
		return { action: "manage", subject };
	}

	return { action, subject };
}
