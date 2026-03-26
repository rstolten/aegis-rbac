import { describe, expect, test } from "bun:test";
import { Hono } from "hono";
import { defineRoles } from "../src/define";
import { createRBACMiddleware } from "../src/middleware/hono";

const config = defineRoles({
	roles: {
		owner: { permissions: ["*"] },
		admin: { permissions: ["workspace:update", "members:invite", "brands:*"] },
		viewer: { permissions: ["workspace:read", "brands:read"] },
	},
	hierarchy: ["owner", "admin", "viewer"],
	superAdmin: "owner",
});

function createApp(role: string | undefined) {
	const app = new Hono();

	// Simulate auth middleware that sets role
	app.use("*", async (c, next) => {
		if (role) {
			c.set("workspaceRole", role);
		}
		await next();
	});

	const { requirePermission, requireRole } = createRBACMiddleware({
		config,
		getRole: (c) => (c as any).get("workspaceRole"),
	});

	app.get("/public", (c) => c.json({ ok: true }));
	app.get("/brands", requirePermission("brands:read"), (c) => c.json({ ok: true }));
	app.post("/brands", requirePermission("brands:write"), (c) => c.json({ ok: true }));
	app.put("/workspace", requirePermission("workspace:update"), (c) => c.json({ ok: true }));
	app.delete("/workspace", requireRole("owner"), (c) => c.json({ ok: true }));
	app.post("/members", requirePermission("members:invite"), (c) => c.json({ ok: true }));
	// Multi-permission route: requires both brands:read AND analytics:read
	app.get("/reports", requirePermission("brands:read", "analytics:read"), (c) =>
		c.json({ ok: true }),
	);
	// Role-gated route that does NOT list owner explicitly
	app.post("/settings", requireRole("admin"), (c) => c.json({ ok: true }));

	return app;
}

describe("requirePermission middleware", () => {
	test("allows owner to access everything", async () => {
		const app = createApp("owner");
		expect((await app.request("/brands")).status).toBe(200);
		expect((await app.request("/brands", { method: "POST" })).status).toBe(200);
		expect((await app.request("/workspace", { method: "PUT" })).status).toBe(200);
		expect((await app.request("/members", { method: "POST" })).status).toBe(200);
	});

	test("allows admin permissions", async () => {
		const app = createApp("admin");
		expect((await app.request("/brands")).status).toBe(200);
		expect((await app.request("/brands", { method: "POST" })).status).toBe(200);
		expect((await app.request("/workspace", { method: "PUT" })).status).toBe(200);
		expect((await app.request("/members", { method: "POST" })).status).toBe(200);
	});

	test("restricts viewer to read-only", async () => {
		const app = createApp("viewer");
		expect((await app.request("/brands")).status).toBe(200);
		expect((await app.request("/brands", { method: "POST" })).status).toBe(403);
		expect((await app.request("/workspace", { method: "PUT" })).status).toBe(403);
		expect((await app.request("/members", { method: "POST" })).status).toBe(403);
	});

	test("returns 401 when no role is set", async () => {
		const app = createApp(undefined);
		expect((await app.request("/brands")).status).toBe(401);
	});

	test("does not affect unprotected routes", async () => {
		const app = createApp(undefined);
		expect((await app.request("/public")).status).toBe(200);
	});

	test("multi-permission check requires ALL permissions", async () => {
		const app = createApp("viewer");
		// viewer has brands:read but NOT analytics:read
		expect((await app.request("/reports")).status).toBe(403);
	});

	test("multi-permission check passes when all permissions are met", async () => {
		const app = createApp("owner");
		expect((await app.request("/reports")).status).toBe(200);
	});
});

describe("requireRole middleware", () => {
	test("allows matching role", async () => {
		const app = createApp("owner");
		expect((await app.request("/workspace", { method: "DELETE" })).status).toBe(200);
	});

	test("rejects non-matching role", async () => {
		const app = createApp("viewer");
		expect((await app.request("/workspace", { method: "DELETE" })).status).toBe(403);
	});

	test("super admin bypasses role check even when not in allowedRoles", async () => {
		const app = createApp("owner");
		// /settings requires "admin" role, owner is NOT in allowedRoles but is superAdmin
		expect((await app.request("/settings", { method: "POST" })).status).toBe(200);
	});

	test("non-super-admin cannot bypass role check", async () => {
		const app = createApp("viewer");
		expect((await app.request("/settings", { method: "POST" })).status).toBe(403);
	});

	test("returns 401 when no role is set", async () => {
		const app = createApp(undefined);
		expect((await app.request("/workspace", { method: "DELETE" })).status).toBe(401);
	});
});

describe("error response format", () => {
	test("returns JSON error on 403", async () => {
		const app = createApp("viewer");
		const res = await app.request("/workspace", { method: "PUT" });
		const body = await res.json();
		expect(body).toEqual({ data: null, error: "Forbidden" });
	});

	test("returns JSON error on 401", async () => {
		const app = createApp(undefined);
		const res = await app.request("/brands");
		const body = await res.json();
		expect(body).toEqual({ data: null, error: "Unauthorized" });
	});
});
