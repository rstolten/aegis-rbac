import { describe, expect, test } from "bun:test";
import { parsePermission } from "../src/permission";

describe("parsePermission", () => {
	test("parses wildcard to manage all", () => {
		expect(parsePermission("*")).toEqual({ action: "manage", subject: "all" });
	});

	test("parses resource:action", () => {
		expect(parsePermission("brands:read")).toEqual({ action: "read", subject: "brands" });
	});

	test("parses resource:* to manage resource", () => {
		expect(parsePermission("brands:*")).toEqual({ action: "manage", subject: "brands" });
	});

	test("parses resource-only to manage resource", () => {
		expect(parsePermission("brands")).toEqual({ action: "manage", subject: "brands" });
	});

	test("handles hyphenated resource names", () => {
		expect(parsePermission("api-keys:delete")).toEqual({ action: "delete", subject: "api-keys" });
	});

	test("handles hyphenated action names", () => {
		expect(parsePermission("members:update-role")).toEqual({
			action: "update-role",
			subject: "members",
		});
	});
});

describe("parsePermission runtime validation", () => {
	test("throws on empty string", () => {
		expect(() => parsePermission("")).toThrow('Invalid permission ""');
	});

	test("throws on colon only", () => {
		expect(() => parsePermission(":")).toThrow('Invalid permission ":"');
	});

	test("throws on leading colon", () => {
		expect(() => parsePermission(":read")).toThrow('Invalid permission ":read"');
	});

	test("throws on trailing colon", () => {
		expect(() => parsePermission("brands:")).toThrow('Invalid permission "brands:"');
	});

	test("throws on multiple colons", () => {
		expect(() => parsePermission("a:b:c")).toThrow('Invalid permission "a:b:c"');
	});

	test("throws on wildcard subject *:read", () => {
		expect(() => parsePermission("*:read")).toThrow('Invalid permission "*:read"');
	});

	test("throws on wildcard subject *:*", () => {
		expect(() => parsePermission("*:*")).toThrow('Invalid permission "*:*"');
	});
});
