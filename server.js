// server.js — M365 + Cloudflare provisioner backend
// Deploy to Railway, Render, or any Node.js host

const express = require("express");
const cors = require("cors");

const app = express();
const PORT = process.env.PORT || 3001;

// Allow requests from your Netlify frontend
// Set ALLOWED_ORIGIN env var on Railway to your Netlify URL
// e.g. https://your-app.netlify.app
// During dev you can set it to * or http://localhost:5173
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "*";

app.use(cors({
  origin: ALLOWED_ORIGIN,
  methods: ["POST", "OPTIONS"],
  allowedHeaders: ["Content-Type"],
}));
app.use(express.json({ limit: "2mb" }));

// Health check
app.get("/", (req, res) => {
  res.json({ status: "ok", service: "m365-provisioner-backend" });
});

// ─── ALL PROVISION LOGIC ──────────────────────────────────────────────────────

async function handleProvision(action, creds, data) {
  switch (action) {

    // ── 1. Get Microsoft OAuth token ─────────────────────────────────────────
    case "ms_token": {
      const res = await fetch(
        `https://login.microsoftonline.com/${creds.tenantId}/oauth2/v2.0/token`,
        {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            client_id: creds.clientId,
            client_secret: creds.clientSecret,
            scope: "https://graph.microsoft.com/.default",
            grant_type: "client_credentials",
          }),
        }
      );
      const j = await res.json();
      if (!res.ok) throw new Error(j.error_description || "MS authentication failed");
      return { token: j.access_token };
    }

    // ── 2. Generic Microsoft Graph call ──────────────────────────────────────
    case "graph": {
      const { method, path, body, headers: extraHeaders } = data;
      const needsConsistency = path.includes("endsWith") || path.includes("$count");
      const res = await fetch(`https://graph.microsoft.com/v1.0${path}`, {
        method,
        headers: {
          Authorization: `Bearer ${creds.token}`,
          "Content-Type": "application/json",
          ...(needsConsistency ? { "ConsistencyLevel": "eventual" } : {}),
          ...(extraHeaders || {}),
        },
        body: body ? JSON.stringify(body) : undefined,
      });
      const j = await res.json();
      if (!res.ok) throw new Error(j.error?.message || `Graph ${method} ${path} → ${res.status}`);
      return j;
    }

    // ── 3. Cloudflare: find zone by domain name ───────────────────────────────
    case "cf_find_zone": {
      const res = await fetch(
        `https://api.cloudflare.com/client/v4/zones?name=${data.domain}`,
        {
          headers: {
            "X-Auth-Email": creds.cfEmail,
            "X-Auth-Key": creds.cfApiKey,
            "Content-Type": "application/json",
          },
        }
      );
      const j = await res.json();
      if (!j.success) throw new Error(j.errors?.[0]?.message || "Cloudflare API error");
      if (!j.result || j.result.length === 0)
        throw new Error(`No Cloudflare zone found for "${data.domain}". Make sure the domain is added to your Cloudflare account.`);
      return { zoneId: j.result[0].id, zoneName: j.result[0].name };
    }

    // ── 4. Cloudflare: add or update a DNS record (upsert) ───────────────────
    case "cf_add_record": {
      const cfHeaders = {
        "X-Auth-Email": creds.cfEmail,
        "X-Auth-Key": creds.cfApiKey,
        "Content-Type": "application/json",
      };
      const { zoneId, record } = data;

      // Try to create first
      const createRes = await fetch(
        `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records`,
        { method: "POST", headers: cfHeaders, body: JSON.stringify(record) }
      );
      const createJson = await createRes.json();

      if (createJson.success) return { created: true, record: createJson.result };

      const errMsg = createJson.errors?.[0]?.message || "Cloudflare DNS error";

      // If already exists — find and update (PUT)
      if (errMsg.toLowerCase().includes("already exists")) {
        const listRes = await fetch(
          `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records?type=${record.type}&name=${encodeURIComponent(record.name)}`,
          { headers: cfHeaders }
        );
        const listJson = await listRes.json();
        const existing = listJson.result?.[0];

        if (existing) {
          const updateRes = await fetch(
            `https://api.cloudflare.com/client/v4/zones/${zoneId}/dns_records/${existing.id}`,
            { method: "PUT", headers: cfHeaders, body: JSON.stringify(record) }
          );
          const updateJson = await updateRes.json();
          if (updateJson.success) return { updated: true, record: updateJson.result };
          return { skipped: true, message: updateJson.errors?.[0]?.message || "Update failed" };
        }
        return { skipped: true, message: "Record exists but could not be located for update" };
      }

      throw new Error(errMsg);
    }

    // ── 5. Enable DKIM — poll public DNS until CNAMEs resolve ────────────────
    case "enable_dkim": {
      const { domain } = data;

      // Verify domain exists and is verified
      const domainRes = await fetch(
        `https://graph.microsoft.com/v1.0/domains/${encodeURIComponent(domain)}`,
        { headers: { Authorization: `Bearer ${creds.token}` } }
      );
      const domainJson = await domainRes.json();
      if (!domainRes.ok) throw new Error(domainJson.error?.message || "Domain not accessible");
      if (!domainJson.isVerified) throw new Error(`Domain ${domain} not yet verified — DKIM requires a verified domain`);

      // Check DKIM CNAMEs in public DNS via Cloudflare DoH
      const dnsCheck1 = await fetch(
        `https://cloudflare-dns.com/dns-query?name=selector1._domainkey.${domain}&type=CNAME`,
        { headers: { Accept: "application/dns-json" } }
      ).then(r => r.json()).catch(() => ({ Answer: [] }));

      const dnsCheck2 = await fetch(
        `https://cloudflare-dns.com/dns-query?name=selector2._domainkey.${domain}&type=CNAME`,
        { headers: { Accept: "application/dns-json" } }
      ).then(r => r.json()).catch(() => ({ Answer: [] }));

      const sel1 = (dnsCheck1.Answer || []).length > 0;
      const sel2 = (dnsCheck2.Answer || []).length > 0;

      if (!sel1 || !sel2) {
        const missing = [
          !sel1 ? `selector1._domainkey.${domain}` : null,
          !sel2 ? `selector2._domainkey.${domain}` : null,
        ].filter(Boolean).join(", ");
        throw new Error(`DKIM CNAMEs not yet in public DNS: ${missing}`);
      }

      return { enabled: true, domain, sel1, sel2, message: "DKIM CNAMEs are live in public DNS" };
    }

    default:
      throw new Error(`Unknown action: ${action}`);
  }
}

// ─── ROUTE ────────────────────────────────────────────────────────────────────
app.post("/provision", async (req, res) => {
  const { action, creds, data } = req.body || {};

  if (!action) {
    return res.status(400).json({ ok: false, error: "Missing action" });
  }

  try {
    const result = await handleProvision(action, creds || {}, data || {});
    res.json({ ok: true, result });
  } catch (err) {
    res.json({ ok: false, error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`M365 provisioner backend running on port ${PORT}`);
});
