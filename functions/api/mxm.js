// Cloudflare Pages Function – proxies Musixmatch's internal API
// Based on https://github.com/Strvm/musicxmatch-api

const UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

// --- secret extraction (cached per isolate lifetime) ---
let _secret = null;
let _secretTs = 0;

async function getSecret() {
  // cache for 2 hours
  if (_secret && Date.now() - _secretTs < 7200000) return _secret;

  // 1. fetch the musixmatch search page to find all JS chunk URLs
  const pageRes = await fetch("https://www.musixmatch.com/search", {
    headers: { "User-Agent": UA, Cookie: "mxm_bab=AB" },
  });
  const html = await pageRes.text();

  const srcPattern = /src="([^"]*\/_next\/static\/chunks\/[^"]+\.js)"/g;
  const chunkUrls = [];
  let m;
  while ((m = srcPattern.exec(html)) !== null) chunkUrls.push(m[1]);
  if (!chunkUrls.length) throw new Error("No JS chunks found on musixmatch.com");

  // 2. fetch chunks in parallel and search each for the HMAC secret
  const secretPattern = /from\(\s*"([A-Za-z0-9+/=]+)"\s*\.split/;
  const results = await Promise.all(
    chunkUrls.map(async (url) => {
      try {
        const res = await fetch(url, { headers: { "User-Agent": UA } });
        const js = await res.text();
        const match = js.match(secretPattern);
        return match ? match[1] : null;
      } catch { return null; }
    })
  );
  const encoded = results.find(Boolean);
  if (!encoded) throw new Error("HMAC secret not found in any chunk (" + chunkUrls.length + " searched)");

  // reverse the string, then base64-decode
  const reversed = encoded.split("").reverse().join("");
  _secret = atob(reversed);
  _secretTs = Date.now();
  return _secret;
}

// --- HMAC-SHA256 signature (Web Crypto) ---
async function sign(url, secret) {
  const now = new Date();
  const y = String(now.getFullYear());
  const mo = String(now.getMonth() + 1).padStart(2, "0");
  const d = String(now.getDate()).padStart(2, "0");

  const message = url + y + mo + d;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(message)
  );
  const b64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
  return "&signature=" + encodeURIComponent(b64) + "&signature_protocol=sha256";
}

// --- handler ---
export async function onRequest(context) {
  const corsHeaders = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Content-Type": "application/json",
  };

  if (context.request.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  const params = new URL(context.request.url).searchParams;
  const action = params.get("action");
  const q = (params.get("q") || "").trim();
  const trackId = params.get("track_id") || "";

  if (action === "test") {
    try {
      const secret = await getSecret();
      const base = "https://www.musixmatch.com/ws/1.1/";
      // try multiple hosts
      const hosts = [
        "https://apic-desktop.musixmatch.com/ws/1.1/",
        "https://apic.musixmatch.com/ws/1.1/",
        "https://www.musixmatch.com/ws/1.1/"
      ];
      const ep = "track.search?app_id=web-desktop-app-v1.0&format=json&q=hello&f_has_lyrics=true&page_size=1";
      const results = [];
      for (const h of hosts) {
        const fullUrl = h + ep;
        const sig = await sign(fullUrl, secret);
        try {
          const r = await fetch(fullUrl + sig, { headers: { "User-Agent": UA } });
          const t = await r.text();
          results.push({ host: h, status: r.status, ct: r.headers.get("content-type"), preview: t.substring(0, 300) });
        } catch (e) { results.push({ host: h, error: e.message }); }
      }
      return new Response(JSON.stringify({ secretLen: secret.length, results }, null, 2), { headers: corsHeaders });
      const signature = await sign(fullUrl, secret);
      const signedUrl = fullUrl + signature;
      const res = await fetch(signedUrl, { headers: { "User-Agent": UA } });
      const text = await res.text();
      return new Response(JSON.stringify({
        secretLen: secret.length,
        secretPreview: secret.substring(0, 4) + "...",
        status: res.status,
        contentType: res.headers.get("content-type"),
        responsePreview: text.substring(0, 500),
        url: fullUrl
      }, null, 2), { headers: corsHeaders });
    } catch (e) {
      return new Response(JSON.stringify({ error: e.message, stack: e.stack }), { status: 500, headers: corsHeaders });
    }
  }

  if (!action) {
    return new Response(
      JSON.stringify({ error: "missing ?action= (search | lyrics)" }),
      { status: 400, headers: corsHeaders }
    );
  }

  try {
    const secret = await getSecret();
    const base = "https://www.musixmatch.com/ws/1.1/";
    let endpoint;

    if (action === "search") {
      if (!q) {
        return new Response(JSON.stringify({ error: "missing ?q=" }), {
          status: 400,
          headers: corsHeaders,
        });
      }
      endpoint =
        "track.search?app_id=web-desktop-app-v1.0&format=json" +
        "&q=" + encodeURIComponent(q).replace(/%20/g, "+") +
        "&f_has_lyrics=true&page_size=10";
    } else if (action === "lyrics") {
      if (!trackId) {
        return new Response(JSON.stringify({ error: "missing ?track_id=" }), {
          status: 400,
          headers: corsHeaders,
        });
      }
      endpoint =
        "track.lyrics.get?app_id=web-desktop-app-v1.0&format=json" +
        "&track_id=" + trackId;
    } else {
      return new Response(
        JSON.stringify({ error: "action must be 'search' or 'lyrics'" }),
        { status: 400, headers: corsHeaders }
      );
    }

    const fullUrl = base + endpoint;
    const signature = await sign(fullUrl, secret);

    const signedUrl = fullUrl + signature;
    const res = await fetch(signedUrl, {
      headers: { "User-Agent": UA },
    });
    const text = await res.text();
    // musixmatch may return XML on error/bad signature
    if (text.trimStart().startsWith("<")) {
      return new Response(
        JSON.stringify({ error: "API returned non-JSON (possibly bad signature)", status: res.status, url: fullUrl }),
        { status: 502, headers: corsHeaders }
      );
    }
    const data = JSON.parse(text);
    return new Response(JSON.stringify(data), { headers: corsHeaders });
  } catch (e) {
    return new Response(JSON.stringify({ error: e.message }), {
      status: 502,
      headers: corsHeaders,
    });
  }
}
