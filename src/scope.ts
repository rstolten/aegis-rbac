import type { DataScopeConfig, ResolveScopeOptions, ScopeContext, ScopeResolver } from "./types";

/**
 * Define data scope resolvers for each role.
 * Used by projects that need row-level data filtering based on user relationships.
 *
 * @example
 * ```ts
 * const scopes = defineDataScope({
 *   tenant_admin: (ctx) => ({ type: "tenant_admin", tenantId: ctx.tenantId }),
 *   staff: async (ctx) => ({
 *     type: "staff",
 *     groupIds: await getStaffGroups(ctx.userId),
 *   }),
 *   member: async (ctx) => ({
 *     type: "member",
 *     linkedIds: await getMemberLinks(ctx.userId, ctx.tenantId),
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
 * Throws if no scope resolver is defined for the role (unless defaultScope is provided).
 *
 * @example
 * ```ts
 * const scope = await resolveScope(scopes, {
 *   userId: "user-123",
 *   tenantId: "tenant-456",
 *   role: "staff",
 * });
 * // { type: "staff", groupIds: ["group-1", "group-2"] }
 *
 * // With default scope for unhandled roles:
 * const scope = await resolveScope(scopes, ctx, { defaultScope: null });
 * ```
 */
export async function resolveScope<TRole extends string, TScope>(
	config: DataScopeConfig<TRole, TScope>,
	ctx: ScopeContext<TRole>,
	options?: ResolveScopeOptions<TScope>,
): Promise<TScope> {
	const resolver = config[ctx.role] as ScopeResolver<TScope, TRole> | undefined;
	if (!resolver) {
		if (options && "defaultScope" in options) {
			return options.defaultScope as TScope;
		}
		throw new Error(
			`No scope resolver for role "${ctx.role}". Define a resolver or provide a defaultScope`,
		);
	}
	return resolver(ctx);
}
