// Cloudflare Pages Function: Musixmatch proxy
// Replicates the Python musicxmatch_api package logic exactly

const USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";
const BASE_URL = "https://www.musixmatch.com/ws/1.1/";

// Cache the secret in global scope (persists across requests in same isolate)
let cachedSecret = null;
let cachedAt = 0;
const CACHE_TTL = 3600000; // 1 hour

async function getLatestAppUrl() {
  const r = await fetch("https://www.musixmatch.com/search", {
    headers: {
      "User-Agent": USER_AGENT,
      "Cookie": "mxm_bab=AB",
    },
  });
  const html = await r.text();

  // Try the exact pattern from the Python library first
  const pattern = /src="([^"]*\/_next\/static\/chunks\/pages\/_app-[^"]+\.js)"/g;
  const matches = [...html.matchAll(pattern)];
  if (matches.length) {
    return matches[matches.length - 1][1];
  }

  // Fallback: search all JS chunk URLs for the one containing the secret pattern
  const allPattern = /src="([^"]*\/_next\/static\/chunks\/[^"]+\.js)"/g;
  const allMatches = [...html.matchAll(allPattern)];
  for (const m of allMatches) {
    const url = m[1];
    try {
      const jsR = await fetch(url, { headers: { "User-Agent": USER_AGENT } });
      const js = await jsR.text();
      if (js.includes('from("') && js.includes('.split')) {
        return url;
      }
    } catch (_) {}
  }

  throw new Error("Could not find _app JS URL");
}

async function getSecret() {
  if (cachedSecret && Date.now() - cachedAt < CACHE_TTL) {
    return cachedSecret;
  }

  const appUrl = await getLatestAppUrl();
  const r = await fetch(appUrl, {
    headers: { "User-Agent": USER_AGENT },
  });
  const js = await r.text();

  // Extract the encoded string — same regex as Python: from("...".split
  const pattern = /from\(\s*"(.*?)"\s*\.split/;
  const match = js.match(pattern);
  if (!match) {
    throw new Error("Could not find encoded secret in JS");
  }

  const encoded = match[1];
  const reversed = encoded.split("").reverse().join("");
  const decoded = atob(reversed);

  cachedSecret = decoded;
  cachedAt = Date.now();
  return decoded;
}

async function generateSignature(url, secret) {
  const now = new Date();
  const y = String(now.getFullYear());
  const m = String(now.getMonth() + 1).padStart(2, "0");
  const d = String(now.getDate()).padStart(2, "0");

  const message = url + y + m + d;
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(message));
  const b64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
  return "&signature=" + encodeURIComponent(b64) + "&signature_protocol=sha256";
}

async function mxmRequest(endpoint, params, secret) {
  const qs = new URLSearchParams({
    app_id: "web-desktop-app-v1.0",
    format: "json",
    ...params,
  }).toString().replace(/%20/g, "+");

  // Sign with the www URL (that's what the signature is based on)
  const url = BASE_URL + endpoint + "?" + qs;
  const sig = await generateSignature(url, secret);
  const signedUrl = url + sig;

  // Try www first, fall back to apic-desktop if we get non-JSON
  for (const base of [BASE_URL, "https://apic-desktop.musixmatch.com/ws/1.1/"]) {
    const tryUrl = base + endpoint + "?" + qs + sig;
    const r = await fetch(tryUrl, {
      headers: { "User-Agent": USER_AGENT },
    });
    const text = await r.text();
    if (text.trim().startsWith("{")) {
      try { return JSON.parse(text); } catch (_) {}
    }
  }
  throw new Error("Musixmatch returned non-JSON from both endpoints");
}

export async function onRequest(context) {
  const cors = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Content-Type": "application/json",
  };

  if (context.request.method === "OPTIONS") {
    return new Response(null, { headers: cors });
  }

  const url = new URL(context.request.url);
  const action = url.searchParams.get("action");

  try {
    const secret = await getSecret();

    if (action === "debug") {
      // Check each step
      const steps = {};
      try {
        const appUrl = await getLatestAppUrl();
        steps.appUrl = appUrl;
      } catch (e) { steps.appUrlError = e.message; }
      steps.secret = secret ? secret.substring(0, 8) + "..." : null;

      // Try a raw fetch to www
      try {
        const qs = "track.search?app_id=web-desktop-app-v1.0&format=json&q=hello&f_has_lyrics=true&page_size=1&page=1";
        const rawUrl = BASE_URL + qs;
        const sig = await generateSignature(rawUrl, secret);
        const r = await fetch(rawUrl + sig, { headers: { "User-Agent": USER_AGENT } });
        const t = await r.text();
        steps.wwwStatus = r.status;
        steps.wwwFirst100 = t.substring(0, 100);
      } catch (e) { steps.wwwError = e.message; }

      // Try apic-desktop
      try {
        const qs = "track.search?app_id=web-desktop-app-v1.0&format=json&q=hello&f_has_lyrics=true&page_size=1&page=1";
        const rawUrl = "https://apic-desktop.musixmatch.com/ws/1.1/" + qs;
        const sig = await generateSignature(BASE_URL + qs, secret);
        const r = await fetch(rawUrl + sig, { headers: { "User-Agent": USER_AGENT } });
        const t = await r.text();
        steps.apicStatus = r.status;
        steps.apicFirst100 = t.substring(0, 100);
      } catch (e) { steps.apicError = e.message; }

      return new Response(JSON.stringify(steps, null, 2), { headers: cors });
    }

    if (action === "token") {
      // Try to get a user token from the desktop API
      const tokenUrl = "https://apic-desktop.musixmatch.com/ws/1.1/token.get?app_id=web-desktop-app-v1.0&format=json";
      const sig = await generateSignature(BASE_URL + "token.get?app_id=web-desktop-app-v1.0&format=json", secret);
      const r = await fetch(tokenUrl + sig, {
        headers: { "User-Agent": USER_AGENT },
      });
      const t = await r.text();
      return new Response(t, { headers: cors });
    }

    if (action === "sign") {
      // Return a signed URL that the browser can fetch directly from www.musixmatch.com
      const endpoint = url.searchParams.get("endpoint") || "track.search";
      const rawParams = {};
      for (const [k, v] of url.searchParams.entries()) {
        if (k !== "action" && k !== "endpoint") rawParams[k] = v;
      }
      const qs = new URLSearchParams({
        app_id: "web-desktop-app-v1.0",
        format: "json",
        ...rawParams,
      }).toString().replace(/%20/g, "+");
      const fullUrl = BASE_URL + endpoint + "?" + qs;
      const sig = await generateSignature(fullUrl, secret);
      return new Response(JSON.stringify({ url: fullUrl + sig }), { headers: cors });
    }

    if (action === "search") {
      const q = url.searchParams.get("q") || "";
      const usertoken = url.searchParams.get("usertoken") || "";
      const params = {
        q: q,
        f_has_lyrics: "true",
        page_size: "10",
        page: "1",
      };
      if (usertoken) params.usertoken = usertoken;
      const data = await mxmRequest("track.search", params, secret);
      return new Response(JSON.stringify(data), { headers: cors });
    }

    if (action === "lyrics") {
      const trackId = url.searchParams.get("track_id") || "";
      const usertoken = url.searchParams.get("usertoken") || "";
      const params = { track_id: trackId };
      if (usertoken) params.usertoken = usertoken;
      const data = await mxmRequest("track.lyrics.get", params, secret);
      return new Response(JSON.stringify(data), { headers: cors });
    }

    return new Response(
      JSON.stringify({ error: "Use ?action=search&q=... or ?action=lyrics&track_id=..." }),
      { status: 400, headers: cors }
    );
  } catch (e) {
    return new Response(
      JSON.stringify({ error: e.message }),
      { status: 500, headers: cors }
    );
  }
}
