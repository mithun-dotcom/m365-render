const express = require("express");
const cors = require("cors");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 10000;

app.use(cors());
app.use(express.json());

// ── Serve frontend ────────────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, "public")));

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
  // Try exact match first, then apex
  const parts = domain.split(".");
  const apex = parts.slice(-2).join(".");
  const res = await cfRequest(cfToken, "GET", `/zones?name=${apex}&status=active`);
  if (res.result && res.result.length > 0) return res.result[0].id;
  throw new Error(`No Cloudflare zone found for "${domain}" (apex: ${apex})`);
}

// ── Main route ─────────────────────────────────────────────────────────────
app.post("/graph", async (req, res) => {
  const {
    action, tenantId, clientId, clientSecret,
    domain, userId, accessToken, cfToken,
    firstName, lastName, password, upn,
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
      const data = await graph(accessToken, "GET", `/domains/${domain}/verificationDnsRecords`);
      const serviceData = await graph(accessToken, "GET", `/domains/${domain}/serviceConfigurationRecords`);
      const all = [...(data.value || []), ...(serviceData.value || [])];
      return res.json({ records: all });
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

      for (const rec of (records || [])) {
        try {
          // Map MS Graph record types to Cloudflare format
          let type = rec["@odata.type"]?.split(".").pop() || rec.recordType;
          let cfRec = null;

          if (type === "txtRecord" || rec.text) {
            cfRec = { type: "TXT", name: rec.label || "@", content: rec.text || rec.supportsTxt, ttl: 3600 };
          } else if (type === "mxRecord" || rec.mailExchange) {
            cfRec = { type: "MX", name: rec.label || "@", content: rec.mailExchange, priority: rec.preference || 10, ttl: 3600 };
          } else if (type === "cnameRecord" || rec.canonicalName) {
            cfRec = { type: "CNAME", name: rec.label, content: rec.canonicalName, ttl: 3600, proxied: false };
          } else {
            continue;
          }

          await cfRequest(cfToken, "POST", `/zones/${zoneId}/dns_records`, cfRec);
          pushed.push(cfRec.type);
        } catch (e) {
          // Record already exists is fine
          if (e.message.includes("already exists")) { pushed.push("(existing)"); continue; }
          failed.push(e.message);
        }
      }
      return res.json({ ok: true, pushed, failed });
    }

    // ── Test Cloudflare connection ──────────────────────────────────────
    if (action === "testCloudflare") {
      if (!cfToken) throw new Error("No token provided");
      const res2 = await cfRequest(cfToken, "GET", "/zones?per_page=1");
      return res.json({ ok: true, zoneCount: res2.result_info?.total_count || 0 });
    }

    // ── Create user ─────────────────────────────────────────────────────
    if (action === "createUser") {
      const displayName = `${firstName} ${lastName}`;
      const userPrincipalName = upn || `${firstName.toLowerCase()}.${lastName.toLowerCase()}@${domain}`;
      await graph(accessToken, "POST", "/users", {
        accountEnabled: true,
        displayName,
        givenName: firstName,
        surname: lastName,
        userPrincipalName,
        mailNickname: firstName.toLowerCase(),
        passwordProfile: { password, forceChangePasswordNextSignIn: false },
        usageLocation: usageLocation || "US",
      });
      return res.json({ ok: true, upn: userPrincipalName });
    }

    // ── Assign license ──────────────────────────────────────────────────
    if (action === "assignLicense") {
      await graph(accessToken, "POST", `/users/${upn}/assignLicense`, {
        addLicenses: [{ skuId, disabledPlans: [] }],
        removeLicenses: [],
      });
      return res.json({ ok: true });
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
