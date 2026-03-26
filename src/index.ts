// Config
export { defineRoles } from "./define";
export { defineDataScope, resolveScope } from "./scope";

// Core
export { buildAbility } from "./ability";
export { can, authorize } from "./check";
export { parsePermission } from "./permission";

// Types
export type {
	Permission,
	RoleConfig,
	RBACConfig,
	ParsedPermission,
	AppAbility,
	ScopeContext,
	ScopeResolver,
	DataScopeConfig,
} from "./types";
