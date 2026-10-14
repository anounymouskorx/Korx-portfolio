import { getStore } from "@netlify/blobs";
import { createHash, timingSafeEqual } from "node:crypto";

// Public list of projects (GET) and owner-only "add project" (POST).
// The passcode is checked here on the server. It lives in the Netlify
// environment variable ADMIN_PASSCODE and is never sent to visitors.
export const config = { path: "/api/projects" };

const MAX_PROJECTS = 100;
const MAX_FAILS = 5;
const LOCK_MS = 15 * 60 * 1000;

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });

const digest = (s) => createHash("sha256").update(String(s)).digest();

function passcodeMatches(input) {
  const real = process.env.ADMIN_PASSCODE || "";
  if (!real) return false;
  return timingSafeEqual(digest(input.trim().toUpperCase()), digest(real.trim().toUpperCase()));
}

function normalizeUrl(raw) {
  if (!raw) return null;
  let s = String(raw).trim();
  if (s.length > 2000) return null;
  if (!/^https?:\/\//i.test(s)) {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) return null;
    s = "https://" + s;
  }
  let u;
  try {
    u = new URL(s);
  } catch {
    return null;
  }
  if (u.protocol !== "https:" && u.protocol !== "http:") return null;
  if (u.username || u.password) return null;
  if (!u.hostname.includes(".")) return null;
  return u;
}

export default async (req, context) => {
  const projects = getStore("korx-projects");

  if (req.method === "GET") {
    const list = (await projects.get("list", { type: "json" })) || [];
    return json({ projects: list });
  }

  if (req.method !== "POST") return json({ error: "method_not_allowed" }, 405);
  if (!process.env.ADMIN_PASSCODE) return json({ error: "not_configured" }, 500);

  let body;
  try {
    body = await req.json();
  } catch {
    return json({ error: "bad_request" }, 400);
  }
  if (!body || typeof body !== "object") return json({ error: "bad_request" }, 400);

  // Slow down guessing: 5 wrong passcodes lock that visitor out for 15 minutes.
  const locks = getStore("korx-locks");
  const lockKey = "ip-" + createHash("sha256").update(String(context.ip || "unknown")).digest("hex").slice(0, 32);
  const lock = (await locks.get(lockKey, { type: "json" })) || { fails: 0, until: 0 };
  if (lock.until > Date.now()) {
    return json({ error: "locked", retryAfter: Math.ceil((lock.until - Date.now()) / 1000) }, 429);
  }

  const given = typeof body.passcode === "string" && body.passcode.length <= 200 ? body.passcode : "";
  if (!given || !passcodeMatches(given)) {
    lock.fails = (lock.fails || 0) + 1;
    if (lock.fails >= MAX_FAILS) {
      lock.fails = 0;
      lock.until = Date.now() + LOCK_MS;
    }
    await locks.setJSON(lockKey, lock);
    return json({ error: "wrong_passcode" }, 401);
  }
  if (lock.fails) await locks.setJSON(lockKey, { fails: 0, until: 0 });

  if (body.action === "verify") return json({ ok: true });

  if (body.action === "add") {
    const u = normalizeUrl(body.url);
    if (!u) return json({ error: "bad_url" }, 400);
    let list = (await projects.get("list", { type: "json" })) || [];
    if (list.some((p) => p.url === u.href)) return json({ error: "duplicate" }, 409);
    if (list.length >= MAX_PROJECTS) return json({ error: "full" }, 400);
    list = [{ url: u.href, added: new Date().toISOString() }, ...list];
    await projects.setJSON("list", list);
    return json({ ok: true, projects: list });
  }

  return json({ error: "bad_request" }, 400);
};
