import { describe, expect, test } from "bun:test";
import { defineRoles } from "../src/define";
import { isRoleAtOrAbove } from "../src/hierarchy";

const config = defineRoles({
	roles: {
		owner: { permissions: ["*"] },
		admin: { permissions: ["workspace:update"] },
		manager: { permissions: ["brands:read"] },
		viewer: { permissions: ["brands:read"] },
	},
	hierarchy: ["owner", "admin", "manager", "viewer"],
});

const flatConfig = defineRoles({
	roles: {
		admin: { permissions: ["workspace:update"] },
		viewer: { permissions: ["brands:read"] },
	},
});

describe("isRoleAtOrAbove", () => {
	test("higher role is at or above lower role", () => {
		expect(isRoleAtOrAbove(config, "owner", "admin")).toBe(true);
		expect(isRoleAtOrAbove(config, "owner", "viewer")).toBe(true);
		expect(isRoleAtOrAbove(config, "admin", "manager")).toBe(true);
	});

	test("equal role is at or above itself", () => {
		expect(isRoleAtOrAbove(config, "admin", "admin")).toBe(true);
		expect(isRoleAtOrAbove(config, "viewer", "viewer")).toBe(true);
		expect(isRoleAtOrAbove(config, "owner", "owner")).toBe(true);
	});

	test("lower role is not at or above higher role", () => {
		expect(isRoleAtOrAbove(config, "viewer", "admin")).toBe(false);
		expect(isRoleAtOrAbove(config, "manager", "admin")).toBe(false);
		expect(isRoleAtOrAbove(config, "viewer", "owner")).toBe(false);
	});

	test("returns false when no hierarchy is defined", () => {
		expect(isRoleAtOrAbove(flatConfig, "admin", "viewer")).toBe(false);
		expect(isRoleAtOrAbove(flatConfig, "admin", "admin")).toBe(false);
	});

	test("returns false when role is not in hierarchy", () => {
		expect(isRoleAtOrAbove(config, "unknown" as any, "admin")).toBe(false);
		expect(isRoleAtOrAbove(config, "admin", "unknown" as any)).toBe(false);
		expect(isRoleAtOrAbove(config, "unknown" as any, "unknown" as any)).toBe(false);
	});

	test("checks adjacent roles correctly", () => {
		expect(isRoleAtOrAbove(config, "manager", "viewer")).toBe(true);
		expect(isRoleAtOrAbove(config, "viewer", "manager")).toBe(false);
	});
});
