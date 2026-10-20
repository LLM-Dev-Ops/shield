import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { api, resolveAllowedOrigin } from "./index.js";

describe("CORS allowlist", () => {
  const originalOrigins = process.env.CORS_ALLOWED_ORIGINS;

  beforeEach(() => {
    process.env.CORS_ALLOWED_ORIGINS =
      "https://console.example.com, https://admin.example.com";
  });

  afterEach(() => {
    if (originalOrigins === undefined) {
      delete process.env.CORS_ALLOWED_ORIGINS;
    } else {
      process.env.CORS_ALLOWED_ORIGINS = originalOrigins;
    }
  });

  it("matches only exact configured origins", () => {
    expect(resolveAllowedOrigin("https://console.example.com")).toBe(
      "https://console.example.com",
    );
    expect(
      resolveAllowedOrigin("https://console.example.com.evil.test"),
    ).toBeUndefined();
    expect(resolveAllowedOrigin(undefined)).toBeUndefined();
  });

  it("allows server-to-server health checks without CORS headers", async () => {
    const response = await request("/health");

    expect(response.status).toBe(200);
    expect(response.headers.get("access-control-allow-origin")).toBeNull();
  });

  it("echoes an allowed browser origin and varies caches by Origin", async () => {
    const response = await request("/health", {
      headers: { Origin: "https://console.example.com" },
    });

    expect(response.status).toBe(200);
    expect(response.headers.get("access-control-allow-origin")).toBe(
      "https://console.example.com",
    );
    expect(response.headers.get("vary")).toContain("Origin");
  });

  it("does not grant a disallowed browser origin", async () => {
    const response = await request("/health", {
      headers: { Origin: "https://attacker.example" },
    });

    expect(response.status).toBe(200);
    expect(response.headers.get("access-control-allow-origin")).toBeNull();
    expect(response.headers.get("vary")).toContain("Origin");
  });

  it("rejects disallowed preflight requests", async () => {
    const response = await request("/health", {
      method: "OPTIONS",
      headers: { Origin: "https://attacker.example" },
    });

    expect(response.status).toBe(403);
    expect(await response.json()).toEqual({ error: "Origin not allowed" });
  });
});

async function request(path: string, init?: RequestInit): Promise<Response> {
  const server = api.listen(0);
  await new Promise<void>((resolve, reject) => {
    server.once("listening", resolve);
    server.once("error", reject);
  });

  try {
    const address = server.address();
    if (!address || typeof address === "string") {
      throw new Error("Expected an ephemeral TCP listener");
    }
    return await fetch(`http://127.0.0.1:${address.port}${path}`, init);
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    });
  }
}
