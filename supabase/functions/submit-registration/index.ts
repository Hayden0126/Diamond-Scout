// Supabase Edge Function: submit-registration
// Deploy with JWT verification disabled (public parent check-in).
// Set REGISTRATION_HASH_SECRET to a long random secret in Edge Function secrets.
// SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are Supabase-managed secrets.
import { createClient } from "https://esm.sh/@supabase/supabase-js@2";

const allowedOrigin = "https://storied-sopapillas-454e84.netlify.app";
const headers = {
  "Access-Control-Allow-Origin": allowedOrigin,
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "content-type, apikey, authorization, x-client-info",
  "Content-Type": "application/json",
  "Cache-Control": "no-store"
};
function respond(status: number, message: string) {
  return new Response(JSON.stringify({ message }), { status, headers });
}
function clean(v: unknown): string {
  return typeof v === "string" ? v.trim().replace(/\s+/g, " ") : "";
}
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers });
  if (req.method !== "POST") return respond(405, "Method not allowed.");
  if (req.headers.get("origin") !== allowedOrigin)
    return respond(403, "This registration form must be opened from DiamondScout.");
  if (Number(req.headers.get("content-length") || 0) > 4096)
    return respond(413, "Registration is too large.");

  const secret = Deno.env.get("REGISTRATION_HASH_SECRET");
  const serviceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
  const url = Deno.env.get("SUPABASE_URL");
  if (!secret || secret.length < 32 || !serviceKey || !url)
    return respond(503, "Registration setup is incomplete.");

  let body: Record<string, unknown>;
  try {
    const raw = await req.text();
    if (raw.length > 4096) return respond(413, "Registration is too large.");
    body = JSON.parse(raw);
    if (!body || Array.isArray(body) || typeof body !== "object") throw Error("invalid");
  } catch {
    return respond(400, "Please check the registration information.");
  }

  const first = clean(body.first_name);
  const last = clean(body.last_name);
  const division = body.division;
  const positions = body.positions;
  const validPositions = ["P","C","1B","2B","SS","3B","LF","CF","RF"];
  if (!first || first.length > 70 || !last || last.length > 70 ||
      !["9u","10u"].includes(String(division)) ||
      !Array.isArray(positions) || positions.length < 1 || positions.length > 9 ||
      new Set(positions).size !== positions.length ||
      !positions.every(p => typeof p === "string" && validPositions.includes(p)))
    return respond(400, "Enter both names, division, and at least one position.");

  // IP is provided by the hosting platform; never accept it from request JSON.
  // This is a practical anti-spam throttle, not a substitute for a WAF.
  const ip = req.headers.get("x-real-ip") ||
    req.headers.get("cf-connecting-ip") ||
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim();
  if (!ip) return respond(503, "Registration temporarily unavailable.");

  const bytes = new TextEncoder().encode(secret + ":" + ip);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  const hash = Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, "0")).join("");

  const sb = createClient(url, serviceKey, { auth: { persistSession: false, autoRefreshToken: false } });
  const { error } = await sb.rpc("ds_submit_registration", {
    p_first_name: first,
    p_last_name: last,
    p_division: division,
    p_positions: positions.join(", "),
    p_client_hash: hash
  });
  if (error?.message?.includes("REGISTRATION_RATE_LIMIT"))
    return respond(429, "Too many registrations from this connection. Please wait 10 minutes or ask a coach.");
  if (error) {
    console.error("Registration failed:", error.code);
    return respond(503, "Registration could not be saved. Please ask a coach for help.");
  }
  return respond(200, "Registration submitted! Please check in with a coach for your tryout number.");
});
