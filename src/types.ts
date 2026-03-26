import type { MongoAbility } from "@casl/ability";

/** A permission string in "resource:action" format, or "*" for full access */
export type Permission = string;

/** Configuration for a single role */
export interface RoleConfig {
	/** Permissions granted to this role in "resource:action" format */
	permissions: Permission[];
}

/** Full RBAC configuration for a project */
export interface RBACConfig<TRole extends string = string> {
	/** Role definitions mapping role names to their permissions */
	roles: Record<TRole, RoleConfig>;
	/**
	 * Optional role hierarchy (highest to lowest).
	 * Roles inherit all permissions from roles below them.
	 */
	hierarchy?: TRole[];
	/** Optional super admin role that bypasses all permission checks */
	superAdmin?: TRole;
}

/** Parsed permission split into resource and action */
export interface ParsedPermission {
	action: string;
	subject: string;
}

/** CASL ability type used throughout the package */
export type AppAbility = MongoAbility<[string, string]>;

/** Context passed to data scope resolvers */
export interface ScopeContext {
	userId: string;
	tenantId: string;
	role: string;
}

/** A data scope resolver function */
export type ScopeResolver<T = unknown> = (ctx: ScopeContext) => T | Promise<T>;

/** Data scope configuration mapping roles to their scope resolvers */
export type DataScopeConfig<TRole extends string = string, TScope = unknown> = Partial<
	Record<TRole, ScopeResolver<TScope>>
>;
