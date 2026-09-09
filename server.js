const express = require("express");
const cors = require("cors");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 10000;

app.use(cors());
app.use(express.json());

// ── Serve frontend ────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, "public")));

// ── Health / ping endpoint (used to wake the server on Render free tier) ──
app.get("/ping", (req, res) => {
  res.json({ ok: true, status: "awake", time: new Date().toISOString() });
});

// ── Helpers ───────────────────────────────────────────────────────────────
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function getToken(tenantId, clientId, clientSecret) {
  const resp = await fetch(
    `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`,
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "client_credentials",
        client_id: clientId,
        client_secret: clientSecret,
        scope: "https://graph.microsoft.com/.default",
      }),
    }
  );
  const data = await resp.json();
  if (!data.access_token)
    throw new Error(data.error_description || data.error || "Token error");
  return data.access_token;
}

async function graph(token, method, urlPath, reqBody, extraHeaders = {}) {
  const opts = {
    method,
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json",
      ...extraHeaders,
    },
  };
  if (reqBody) opts.body = JSON.stringify(reqBody);

  for (let attempt = 0; attempt < 6; attempt++) {
    const resp = await fetch(`https://graph.microsoft.com/v1.0${urlPath}`, opts);
    if (resp.status === 429) {
      const wait = (parseInt(resp.headers.get("Retry-After") || "15") + 3) * 1000;
      await sleep(wait);
      continue;
    }
    if (resp.status === 204 || resp.status === 404) return { status: resp.status };
    const json = await resp.json();
    if (!resp.ok) throw new Error(json.error?.message || `HTTP ${resp.status}`);
    return json;
  }
  throw new Error("Throttled by Microsoft — retry later.");
}

// ── Cloudflare helper (FIXED — correct Authorization header) ──────────────
async function cfRequest(cfToken, method, urlPath, body) {
  const opts = {
    method,
    headers: {
      // ✅ FIXED: was missing "Bearer " prefix causing "Invalid request headers"
      Authorization: `Bearer ${cfToken}`,
      "Content-Type": "application/json",
    },
  };
  if (body) opts.body = JSON.stringify(body);
  const resp = await fetch(`https://api.cloudflare.com/client/v4${urlPath}`, opts);
  const json = await resp.json();
  if (!json.success) {
    const errMsg = json.errors?.map((e) => e.message).join(", ") || "Cloudflare error";
    throw new Error(errMsg);
  }
  return json;
}

async function getCFZoneId(cfToken, domain) {
  domain = domain.toLowerCase().trim();

  // 1) Try the exact domain first — Cloudflare zone is usually the registered domain
  let res = await cfRequest(cfToken, "GET", `/zones?name=${domain}`);
  if (res.result && res.result.length > 0) return res.result[0].id;

  // 2) Walk the domain labels from most-specific to least, so multi-part
  //    TLDs like "shiredebtltd.co.uk" are matched correctly (slicing the
  //    last 2 labels would wrongly give "co.uk").
  const labels = domain.split(".");
  for (let i = 1; i < labels.length - 1; i++) {
    const candidate = labels.slice(i).join(".");
    res = await cfRequest(cfToken, "GET", `/zones?name=${candidate}`);
    if (res.result && res.result.length > 0) return res.result[0].id;
  }

  // 3) Last resort — list all zones and find one the domain ends with
  const all = await cfRequest(cfToken, "GET", `/zones?per_page=50`);
  const match = (all.result || []).find(
    (z) => domain === z.name || domain.endsWith(`.${z.name}`)
  );
  if (match) return match.id;

  throw new Error(
    `No Cloudflare zone found for "${domain}". Make sure this domain (or its registered root) is added to your Cloudflare account.`
  );
}

// ── Main route ─────────────────────────────────────────────────────────────
app.post("/graph", async (req, res) => {
  const {
    action, tenantId, clientId, clientSecret,
    domain, userId, accessToken, cfToken,
    firstName, lastName, password, upn, displayName,
    usageLocation, skuId, records,
  } = req.body || {};

  try {
    // ── Auth ────────────────────────────────────────────────────────────
    if (action === "auth") {
      const token = await getToken(tenantId, clientId, clientSecret);
      const org = await graph(token, "GET", "/organization");
      const tenantName = org.value?.[0]?.displayName || "Unknown Tenant";
      return res.json({ token, tenantName });
    }

    // ── Add domain ──────────────────────────────────────────────────────
    if (action === "addDomain") {
      try {
        await graph(accessToken, "POST", "/domains", { id: domain });
      } catch (e) {
        // Already exists is fine
        if (!e.message.includes("already exists") && !e.message.includes("ObjectConflict")) throw e;
      }
      return res.json({ ok: true });
    }

    // ── Get DNS verification records from Microsoft ──────────────────────
    if (action === "getDnsRecords") {
      // verificationDnsRecords = TXT/CNAME needed to prove domain ownership
      const verifyData = await graph(accessToken, "GET", `/domains/${domain}/verificationDnsRecords`);
      // serviceConfigurationRecords = MX, CNAME (autodiscover, DKIM selectors), TXT (SPF), SRV
      const serviceData = await graph(accessToken, "GET", `/domains/${domain}/serviceConfigurationRecords`);

      const all = [
        ...(verifyData.value || []),
        ...(serviceData.value || []),
      ];

      // Deduplicate by label+type combo
      const seen = new Set();
      const unique = all.filter(r => {
        const key = `${r["@odata.type"]}|${r.label}|${r.canonicalName||r.text||r.mailExchange||""}`;
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
      });

      console.log(`[getDnsRecords] ${domain} — ${unique.length} records:`,
        unique.map(r => `${r["@odata.type"]?.split(".").pop()} ${r.label}`));

      return res.json({ records: unique });
    }

    // ── Verify domain ───────────────────────────────────────────────────
    if (action === "verifyDomain") {
      try {
        await graph(accessToken, "POST", `/domains/${domain}/verify`, {});
        return res.json({ verified: true });
      } catch (e) {
        return res.json({ verified: false, reason: e.message });
      }
    }

    // ── Push DNS records to Cloudflare ──────────────────────────────────
    if (action === "cloudflare") {
      if (!cfToken) throw new Error("Cloudflare API token not provided");
      const zoneId = await getCFZoneId(cfToken, domain);
      const pushed = [];
      const failed = [];
      let dkimPushed = false;

      // Normalize a Microsoft DNS label into a Cloudflare record name.
      // Microsoft returns the FULL host (e.g. "shiredebtltd.co.uk" for apex,
      // "autodiscover.shiredebtltd.co.uk" for subdomains). Cloudflare treats
      // a bare name as relative to the zone and auto-appends the zone, so we
      // strip the zone suffix and map the apex to "@".
      const normalizeName = (label) => {
        if (!label) return "@";
        let n = label.toLowerCase().trim().replace(/\.$/, "");
        const suffix = `.${domain.toLowerCase()}`;
        if (n === domain.toLowerCase()) return "@";
        if (n.endsWith(suffix)) n = n.slice(0, -suffix.length);
        return n || "@";
      };

      for (const rec of (records || [])) {
        try {
          // Normalize the @odata.type to a simple lowercase key
          const odataType = (rec["@odata.type"] || "").toLowerCase();
          let cfRec = null;

          // ── TXT (SPF, DMARC, domain verification) ──────────────────────
          if (odataType.includes("txt") || rec.text || rec.supportsTxt) {
            const content = rec.text || rec.supportsTxt || "";
            if (!content) continue;
            cfRec = {
              type: "TXT",
              name: normalizeName(rec.label),
              content,
              ttl: 3600,
            };

          // ── MX ──────────────────────────────────────────────────────────
          } else if (odataType.includes("mx") || rec.mailExchange) {
            cfRec = {
              type: "MX",
              name: normalizeName(rec.label),
              content: rec.mailExchange,
              priority: rec.preference || 10,
              ttl: 3600,
            };

          // ── CNAME — covers DKIM (selector1._domainkey, selector2._domainkey)
          //           and autodiscover, msoid, sip, lyncdiscover, etc. ────
          } else if (odataType.includes("cname") || rec.canonicalName) {
            const name = normalizeName(rec.label || rec.name);
            const content = rec.canonicalName || rec.value;
            if (!content) continue;

            const isDkim = name.toLowerCase().includes("_domainkey");
            cfRec = {
              type: "CNAME",
              name,          // e.g. "selector1._domainkey" or "autodiscover"
              content,       // e.g. "selector1-domain-com._domainkey.tenant.onmicrosoft.com"
              ttl: 3600,
              proxied: false, // MUST be false — DKIM/autodiscover CNAMEs can't be proxied
            };
            if (isDkim) dkimPushed = true;

          // ── SRV (Skype/Teams) ────────────────────────────────────────────
          } else if (odataType.includes("srv") || rec.target) {
            cfRec = {
              type: "SRV",
              name: normalizeName(rec.label),
              data: {
                service: rec.nameTarget?.split(".")[0] || rec.label?.split(".")[0] || "_sip",
                proto: rec.label?.includes("tls") ? "_tls" : "_tcp",
                name: domain,
                priority: rec.priority || 100,
                weight: rec.weight || 1,
                port: rec.port || 443,
                target: rec.nameTarget || rec.target,
              },
              ttl: 3600,
            };

          } else {
            // Unknown type — skip silently
            continue;
          }

          await cfRequest(cfToken, "POST", `/zones/${zoneId}/dns_records`, cfRec);
          pushed.push(`${cfRec.type}:${cfRec.name}`);
        } catch (e) {
          // Already exists is fine — treat as success
          if (
            e.message.includes("already exists") ||
            e.message.includes("An identical record already exists")
          ) {
            pushed.push("(existing)");
            continue;
          }
          failed.push(`${rec.label||'?'}: ${e.message}`);
        }
      }
      return res.json({ ok: true, zoneId, pushed, failed, dkimPushed, total: (records||[]).length });
    }

    // ── Test Cloudflare connection ──────────────────────────────────────
    if (action === "testCloudflare") {
      if (!cfToken) throw new Error("No token provided");
      const res2 = await cfRequest(cfToken, "GET", "/zones?per_page=1");
      return res.json({ ok: true, zoneCount: res2.result_info?.total_count || 0 });
    }

    // ── Create user ─────────────────────────────────────────────────────
    if (action === "createUser") {
      // UPN is provided directly (full email). displayName provided directly.
      const userPrincipalName =
        upn || `${firstName.toLowerCase()}.${lastName.toLowerCase()}@${domain}`;

      // Derive display/given/surname
      const dName = (displayName || `${firstName || ""} ${lastName || ""}`).trim();
      const nameParts = dName.split(/\s+/).filter(Boolean);
      const given = firstName || nameParts[0] || dName;
      const sur = lastName || (nameParts.length > 1 ? nameParts.slice(1).join(" ") : "");

      // mailNickname must be unique-ish and alphanumeric — use UPN local part
      const localPart = userPrincipalName.split("@")[0];
      const mailNickname = localPart.replace(/[^a-zA-Z0-9._-]/g, "") || "user";

      await graph(accessToken, "POST", "/users", {
        accountEnabled: true,
        displayName: dName || localPart,
        givenName: given || undefined,
        surname: sur || undefined,
        userPrincipalName,
        mailNickname,
        passwordProfile: { password, forceChangePasswordNextSignIn: false },
        usageLocation: usageLocation || "US",
      });
      return res.json({ ok: true, upn: userPrincipalName });
    }

    // ── Get available licenses (SKUs with free seats) ───────────────────
    if (action === "getAvailableLicenses") {
      const data = await graph(accessToken, "GET", "/subscribedSkus");
      const skus = (data.value || []).map((s) => {
        const enabled = s.prepaidUnits?.enabled || 0;   // total seats purchased
        const consumed = s.consumedUnits || 0;          // seats used
        const available = enabled - consumed;
        return {
          skuId: s.skuId,
          skuPartNumber: s.skuPartNumber,
          enabled,
          consumed,
          available,
          capabilityStatus: s.capabilityStatus,
        };
      })
      // only usable SKUs that still have a free seat
      .filter((s) => s.available > 0 && s.capabilityStatus === "Enabled")
      // first-come order: keep the order Microsoft returns them
      ;
      return res.json({ skus });
    }

    // ── Assign license ──────────────────────────────────────────────────
    // If skuId is provided, use it. Otherwise auto-pick the first SKU that
    // still has an available seat, moving to the next once one runs out.
    if (action === "assignLicense") {
      let chosenSku = skuId;
      let chosenName = null;

      if (!chosenSku) {
        // Auto-select: read live seat counts and pick first with availability
        const data = await graph(accessToken, "GET", "/subscribedSkus");
        const usable = (data.value || [])
          .map((s) => ({
            skuId: s.skuId,
            skuPartNumber: s.skuPartNumber,
            available: (s.prepaidUnits?.enabled || 0) - (s.consumedUnits || 0),
            capabilityStatus: s.capabilityStatus,
          }))
          .filter((s) => s.available > 0 && s.capabilityStatus === "Enabled");

        if (!usable.length) {
          throw new Error("No available licenses — all SKUs are fully consumed");
        }
        chosenSku = usable[0].skuId;          // first one with a free seat
        chosenName = usable[0].skuPartNumber;
      }

      await graph(accessToken, "POST", `/users/${upn}/assignLicense`, {
        addLicenses: [{ skuId: chosenSku, disabledPlans: [] }],
        removeLicenses: [],
      });
      return res.json({ ok: true, skuId: chosenSku, skuPartNumber: chosenName });
    }

    // ── List users on domain ────────────────────────────────────────────
    if (action === "listUsers") {
      try {
        const filter = encodeURIComponent(`endsWith(userPrincipalName,'@${domain}')`);
        const data = await graph(accessToken, "GET",
          `/users?$filter=${filter}&$select=id,displayName,userPrincipalName,assignedRoles&$count=true`,
          null, { ConsistencyLevel: "eventual" }
        );
        return res.json({ users: data.value || [] });
      } catch {
        let users = [], url = `/users?$select=id,displayName,userPrincipalName&$top=999`;
        while (url) {
          const data = await graph(accessToken, "GET", url);
          users = users.concat((data.value || []).filter(u =>
            u.userPrincipalName?.toLowerCase().endsWith(`@${domain.toLowerCase()}`)
          ));
          url = data["@odata.nextLink"]?.replace("https://graph.microsoft.com/v1.0", "") || null;
        }
        return res.json({ users });
      }
    }

    // ── Check admin role (skip if admin) ────────────────────────────────
    if (action === "checkAdmin") {
      try {
        const data = await graph(accessToken, "GET", `/users/${userId}/memberOf`);
        const roles = (data.value || []).filter(r =>
          r["@odata.type"] === "#microsoft.graph.directoryRole"
        );
        return res.json({ isAdmin: roles.length > 0, roles: roles.map(r => r.displayName) });
      } catch {
        return res.json({ isAdmin: false, roles: [] });
      }
    }

    // ── Delete user ─────────────────────────────────────────────────────
    if (action === "deleteUser") {
      await graph(accessToken, "DELETE", `/users/${userId}`);
      return res.json({ ok: true });
    }

    // ── Check domain exists ─────────────────────────────────────────────
    if (action === "checkDomain") {
      try {
        const d = await graph(accessToken, "GET", `/domains/${domain}`);
        return res.json({ exists: !!(d && d.id) });
      } catch (e) {
        return res.json({ exists: false, reason: e.message });
      }
    }

    // ── Remove domain ───────────────────────────────────────────────────
    if (action === "removeDomain") {
      await graph(accessToken, "DELETE", `/domains/${domain}`);
      return res.json({ ok: true });
    }

    // ── Reset password ──────────────────────────────────────────────────
    if (action === "resetPassword") {
      await graph(accessToken, "PATCH", `/users/${userId}`, {
        passwordProfile: { password, forceChangePasswordNextSignIn: false },
      });
      return res.json({ ok: true });
    }

    return res.status(400).json({ error: `Unknown action: ${action}` });

  } catch (err) {
    console.error(`[${action}]`, err.message);
    return res.status(500).json({ error: err.message });
  }
});

// ── Fallback to index.html for SPA ────────────────────────────────────────
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
