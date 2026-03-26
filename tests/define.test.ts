import { describe, expect, test } from "bun:test";
import { defineRoles } from "../src/define";

describe("defineRoles validation", () => {
	test("freezes the config", () => {
		const config = defineRoles({
			roles: { admin: { permissions: ["workspace:read"] } },
		});
		expect(Object.isFrozen(config)).toBe(true);
	});

	test("deep freezes nested role objects", () => {
		const config = defineRoles({
			roles: { admin: { permissions: ["workspace:read"] } },
		});
		expect(Object.isFrozen(config.roles)).toBe(true);
		expect(Object.isFrozen(config.roles.admin)).toBe(true);
		expect(Object.isFrozen(config.roles.admin.permissions)).toBe(true);
	});

	test("prevents mutation of permissions array after creation", () => {
		const config = defineRoles({
			roles: { admin: { permissions: ["workspace:read"] } },
		});
		expect(() => {
			(config.roles.admin.permissions as string[]).push(":broken");
		}).toThrow();
	});

	test("prevents mutation of role config after creation", () => {
		const config = defineRoles({
			roles: { admin: { permissions: ["workspace:read"] } },
		});
		expect(() => {
			(config.roles as any).admin = { permissions: ["*"] };
		}).toThrow();
	});

	test("throws on empty roles", () => {
		expect(() => defineRoles({ roles: {} as any })).toThrow("at least one role");
	});

	test("throws on empty permission string", () => {
		expect(() => defineRoles({ roles: { admin: { permissions: [""] } } })).toThrow(
			'Invalid permission ""',
		);
	});

	test("throws on permission starting with colon", () => {
		expect(() => defineRoles({ roles: { admin: { permissions: [":read"] } } })).toThrow(
			'Invalid permission ":read"',
		);
	});

	test("throws on permission ending with colon", () => {
		expect(() => defineRoles({ roles: { admin: { permissions: ["brands:"] } } })).toThrow(
			'Invalid permission "brands:"',
		);
	});

	test("throws on permission with multiple colons", () => {
		expect(() => defineRoles({ roles: { admin: { permissions: ["a:b:c"] } } })).toThrow(
			'Invalid permission "a:b:c"',
		);
	});

	test("throws on wildcard subject *:read", () => {
		expect(() => defineRoles({ roles: { admin: { permissions: ["*:read"] } } })).toThrow(
			'Invalid permission "*:read"',
		);
	});

	test("throws on wildcard subject *:*", () => {
		expect(() => defineRoles({ roles: { admin: { permissions: ["*:*"] } } })).toThrow(
			'Invalid permission "*:*"',
		);
	});

	test("accepts valid permission formats", () => {
		expect(() =>
			defineRoles({
				roles: {
					admin: { permissions: ["*", "brands", "brands:read", "brands:*"] },
				},
			}),
		).not.toThrow();
	});

	test("throws when hierarchy references unknown role", () => {
		expect(() =>
			defineRoles({
				roles: { admin: { permissions: ["*"] } },
				hierarchy: ["admin", "viewer"] as any,
			}),
		).toThrow('unknown role "viewer"');
	});

	test("throws when superAdmin references unknown role", () => {
		expect(() =>
			defineRoles({
				roles: { admin: { permissions: ["*"] } },
				superAdmin: "owner" as any,
			}),
		).toThrow('unknown role "owner"');
	});

	test("accepts valid config with hierarchy and superAdmin", () => {
		expect(() =>
			defineRoles({
				roles: {
					owner: { permissions: ["*"] },
					admin: { permissions: ["workspace:update"] },
					viewer: { permissions: ["workspace:read"] },
				},
				hierarchy: ["owner", "admin", "viewer"],
				superAdmin: "owner",
			}),
		).not.toThrow();
	});
});
