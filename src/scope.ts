import type { DataScopeConfig, ScopeContext, ScopeResolver } from "./types";

/**
 * Define data scope resolvers for each role.
 * Used by projects that need row-level data filtering based on user relationships.
 *
 * @example
 * ```ts
 * const scopes = defineDataScope({
 *   school_admin: (ctx) => ({ type: "school_admin", schoolId: ctx.tenantId }),
 *   teacher: async (ctx) => ({
 *     type: "teacher",
 *     classIds: await getTeacherClasses(ctx.userId),
 *   }),
 *   parent: async (ctx) => ({
 *     type: "parent",
 *     childIds: await getParentChildren(ctx.userId, ctx.tenantId),
 *   }),
 * });
 * ```
 */
export function defineDataScope<TRole extends string, TScope>(
	config: DataScopeConfig<TRole, TScope>,
): DataScopeConfig<TRole, TScope> {
	return Object.freeze(config);
}

/**
 * Resolve the data scope for a user based on their role.
 * Returns undefined if no scope resolver is defined for the role.
 *
 * @example
 * ```ts
 * const scope = await resolveScope(scopes, {
 *   userId: "user-123",
 *   tenantId: "school-456",
 *   role: "teacher",
 * });
 * // { type: "teacher", classIds: ["class-1", "class-2"] }
 * ```
 */
export async function resolveScope<TRole extends string, TScope>(
	config: DataScopeConfig<TRole, TScope>,
	ctx: ScopeContext,
): Promise<TScope | undefined> {
	const resolver = config[ctx.role as TRole] as ScopeResolver<TScope> | undefined;
	if (!resolver) return undefined;
	return resolver(ctx);
}
