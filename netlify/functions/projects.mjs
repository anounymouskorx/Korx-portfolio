import { getStore } from "@netlify/blobs";
import { createHash, randomUUID, timingSafeEqual } from "node:crypto";

// One server function for the whole site.
//   GET  /api/projects              public list of projects
//   GET  /api/projects?img=<id>     a project's picture
//   POST /api/projects  action "enquiry"          a visitor sends an enquiry
//   POST /api/projects  action "verify"           check the admin passcode
//   POST /api/projects  action "add"              add a project (passcode needed)
//   POST /api/projects  action "list_enquiries"   read enquiries (passcode needed)
// The passcode lives in the Netlify environment variable ADMIN_PASSCODE and
// is never sent to visitors.
export const config = { path: "/api/projects" };

const MAX_PROJECTS = 100;
const MAX_ENQUIRIES = 200;
const MAX_FAILS = 5;
const LOCK_MS = 15 * 60 * 1000;
const ENQ_PER_HOUR = 5;
const MAX_BODY = 1_500_000;
const MAX_IMAGE_BYTES = 700_000;
const IMAGE_ID = /^[a-f0-9-]{36}$/;
const JPEG_URL = /^data:image\/jpeg;base64,([A-Za-z0-9+/]+={0,2})$/;

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store" },
  });

const digest = (s) => createHash("sha256").update(String(s)).digest();
const visitorKey = (prefix, ip) =>
  prefix + createHash("sha256").update(String(ip || "unknown")).digest("hex").slice(0, 32);
const text = (v, max) => (typeof v === "string" ? v.trim().slice(0, max) : "");

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
  const images = getStore("korx-images");
  const enquiries = getStore("korx-enquiries");
  const locks = getStore("korx-locks");

  if (req.method === "GET") {
    const imgId = new URL(req.url).searchParams.get("img");
    if (imgId !== null) {
      if (!IMAGE_ID.test(imgId)) return json({ error: "not_found" }, 404);
      const data = await images.get(imgId, { type: "arrayBuffer" });
      if (!data) return json({ error: "not_found" }, 404);
      return new Response(data, {
        headers: {
          "content-type": "image/jpeg",
          "cache-control": "public, max-age=31536000, immutable",
          "x-content-type-options": "nosniff",
        },
      });
    }
    const list = (await projects.get("list", { type: "json" })) || [];
    return json({ projects: list });
  }

  if (req.method !== "POST") return json({ error: "method_not_allowed" }, 405);

  let body;
  try {
    const raw = await req.text();
    if (raw.length > MAX_BODY) return json({ error: "too_large" }, 413);
    body = JSON.parse(raw);
  } catch {
    return json({ error: "bad_request" }, 400);
  }
  if (!body || typeof body !== "object") return json({ error: "bad_request" }, 400);

  // Public: a visitor sends an enquiry. Limited to 5 per hour per visitor.
  if (body.action === "enquiry") {
    if (text(body["bot-field"], 50)) return json({ ok: true });
    const name = text(body.name, 80);
    const contact = text(body.contact, 120);
    const need = text(body.need, 40);
    const message = text(body.message, 2000);
    if (!name || !contact || !message) return json({ error: "missing" }, 400);

    const key = visitorKey("enq-", context.ip);
    const now = Date.now();
    let rl = (await locks.get(key, { type: "json" })) || { count: 0, start: now };
    if (now - rl.start > 60 * 60 * 1000) rl = { count: 0, start: now };
    if (rl.count >= ENQ_PER_HOUR) return json({ error: "rate_limited" }, 429);
    rl.count += 1;
    await locks.setJSON(key, rl);

    let list = (await enquiries.get("list", { type: "json" })) || [];
    list = [{ id: randomUUID(), name, contact, need, message, at: new Date().toISOString() }, ...list].slice(0, MAX_ENQUIRIES);
    await enquiries.setJSON("list", list);
    return json({ ok: true });
  }

  // Everything below is admin only.
  if (!process.env.ADMIN_PASSCODE) return json({ error: "not_configured" }, 500);

  // Slow down guessing: 5 wrong passcodes lock that visitor out for 15 minutes.
  const lockKey = visitorKey("ip-", context.ip);
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

  if (body.action === "list_enquiries") {
    const list = (await enquiries.get("list", { type: "json" })) || [];
    return json({ enquiries: list });
  }

  if (body.action === "add") {
    const u = normalizeUrl(body.url);
    if (!u) return json({ error: "bad_url" }, 400);

    let bytes = null;
    if (body.image) {
      const m = typeof body.image === "string" ? JPEG_URL.exec(body.image) : null;
      const buf = m ? Buffer.from(m[1], "base64") : null;
      const looksLikeJpeg = buf && buf.length >= 500 && buf.length <= MAX_IMAGE_BYTES && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff;
      if (!looksLikeJpeg) return json({ error: "bad_image" }, 400);
      bytes = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
    }

    let list = (await projects.get("list", { type: "json" })) || [];
    if (list.some((p) => p.url === u.href)) return json({ error: "duplicate" }, 409);
    if (list.length >= MAX_PROJECTS) return json({ error: "full" }, 400);

    const entry = { url: u.href, added: new Date().toISOString() };
    if (bytes) {
      const id = randomUUID();
      await images.set(id, bytes);
      entry.image = id;
    }
    list = [entry, ...list];
    await projects.setJSON("list", list);
    return json({ ok: true, projects: list });
  }

  return json({ error: "bad_request" }, 400);
};
