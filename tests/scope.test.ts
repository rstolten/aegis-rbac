import { describe, expect, test } from "bun:test";
import { defineDataScope, resolveScope } from "../src/scope";

type Scope =
	| { type: "admin"; tenantId: string }
	| { type: "teacher"; classIds: string[] }
	| { type: "parent"; childIds: string[] };

const scopes = defineDataScope<"admin" | "teacher" | "parent", Scope>({
	admin: (ctx) => ({ type: "admin", tenantId: ctx.tenantId }),
	teacher: async (ctx) => ({
		type: "teacher",
		classIds: [`class-for-${ctx.userId}`],
	}),
	parent: async (ctx) => ({
		type: "parent",
		childIds: [`child-of-${ctx.userId}`],
	}),
});

describe("defineDataScope", () => {
	test("freezes the config", () => {
		expect(Object.isFrozen(scopes)).toBe(true);
	});
});

describe("resolveScope", () => {
	test("resolves admin scope synchronously", async () => {
		const scope = await resolveScope(scopes, {
			userId: "user-1",
			tenantId: "school-1",
			role: "admin",
		});
		expect(scope).toEqual({ type: "admin", tenantId: "school-1" });
	});

	test("resolves teacher scope asynchronously", async () => {
		const scope = await resolveScope(scopes, {
			userId: "teacher-1",
			tenantId: "school-1",
			role: "teacher",
		});
		expect(scope).toEqual({ type: "teacher", classIds: ["class-for-teacher-1"] });
	});

	test("resolves parent scope asynchronously", async () => {
		const scope = await resolveScope(scopes, {
			userId: "parent-1",
			tenantId: "school-1",
			role: "parent",
		});
		expect(scope).toEqual({ type: "parent", childIds: ["child-of-parent-1"] });
	});

	test("returns undefined for unknown role", async () => {
		const scope = await resolveScope(scopes, {
			userId: "user-1",
			tenantId: "school-1",
			role: "unknown" as any,
		});
		expect(scope).toBeUndefined();
	});
});
