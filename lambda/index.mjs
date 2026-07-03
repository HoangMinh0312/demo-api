/**
 * Linear -> GitHub relay (AWS Lambda + API Gateway)
 *
 * Ban Lambda cua worker.js: nhan webhook Issue tu Linear, verify chu ky
 * HMAC, kiem tra label "ai-agent" vua duoc GAN VAO, roi ban
 * repository_dispatch sang GitHub de trigger workflow linear-agent.yml.
 *
 * Runtime: Node.js 20.x hoac 22.x, handler: index.handler
 * Ho tro ca API Gateway HTTP API (payload v2), REST API (v1) va Function URL.
 *
 * Env vars can set trong Lambda Configuration:
 *   LINEAR_WEBHOOK_SECRET  - signing secret cua webhook trong Linear
 *   GITHUB_TOKEN           - fine-grained PAT, quyen: Contents R/W tren repo
 *   GITHUB_OWNER           - org/user cua repo dich
 *   GITHUB_REPO            - ten repo dich
 *   TRIGGER_LABEL          - (tuy chon) mac dinh "ai-agent"
 */

import { createHmac, timingSafeEqual } from "node:crypto";

export const handler = async (event) => {
  // API GW v2 / Function URL de method o requestContext.http, REST API v1 o httpMethod
  const method = event.requestContext?.http?.method || event.httpMethod || "";
  if (method !== "POST") {
    console.log(`Rejected: method=${method || "(empty)"}`);
    return respond(405, "Method not allowed");
  }

  // Body co the bi base64-encode tuy cau hinh integration
  const rawBody = event.isBase64Encoded
    ? Buffer.from(event.body || "", "base64").toString("utf8")
    : event.body || "";

  // Header key khong phan biet hoa thuong tuy nguon, normalize ve lowercase
  const headers = Object.fromEntries(
    Object.entries(event.headers || {}).map(([k, v]) => [k.toLowerCase(), v])
  );

  // 1. Verify chu ky: Linear gui HMAC-SHA256(rawBody) hex trong header
  const signature = headers["linear-signature"] || "";
  if (!verifySignature(rawBody, signature, process.env.LINEAR_WEBHOOK_SECRET)) {
    // Khong log gia tri signature/body de tranh lo du lieu
    console.warn(
      `Rejected: invalid signature (header ${signature ? "present" : "missing"},` +
        ` secret ${process.env.LINEAR_WEBHOOK_SECRET ? "set" : "NOT SET"})`
    );
    return respond(401, "Invalid signature");
  }

  let payload;
  try {
    payload = JSON.parse(rawBody);
  } catch {
    console.warn("Rejected: body is not valid JSON");
    return respond(400, "Invalid JSON body");
  }

  console.log(
    `Received: type=${payload.type} action=${payload.action}` +
      ` issue=${payload.data?.identifier || "?"}`
  );

  // 2. Chi quan tam Issue create/update
  if (payload.type !== "Issue" || !["create", "update"].includes(payload.action)) {
    console.log("Ignored: not an issue create/update event");
    return respond(200, "Ignored: not an issue event");
  }

  const data = payload.data || {};
  const triggerLabel = (process.env.TRIGGER_LABEL || "ai-agent").toLowerCase();

  // 3. Kiem tra label hien tai co "ai-agent" khong
  const labels = (data.labels || []).map((l) => (l.name || "").toLowerCase());
  if (!labels.includes(triggerLabel)) {
    console.log(
      `Ignored: ${data.identifier} missing label "${triggerLabel}"` +
        ` (labels: ${labels.join(", ") || "none"})`
    );
    return respond(200, "Ignored: trigger label not present");
  }

  // 4. Chong ban trung: voi action=update, chi fire khi label VUA duoc them
  //    (updatedFrom.labelIds ton tai nghia la labelIds vua thay doi)
  if (payload.action === "update" && !payload.updatedFrom?.labelIds) {
    console.log(`Ignored: ${data.identifier} updated but label set unchanged`);
    return respond(200, "Ignored: label set unchanged");
  }

  // 5. Chuan bi payload cho GitHub
  const identifier = data.identifier; // vi du "NA-123"
  const slug = (data.title || "task")
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "") // bo dau tieng Viet
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 40);

  const clientPayload = {
    identifier,
    title: data.title || "",
    description: (data.description || "").slice(0, 60000),
    url: data.url || "",
    // Branch chua ma ticket -> Linear GitHub integration tu dong link
    branchName: `claude/${identifier.toLowerCase()}-${slug}`,
  };

  // 6. Ban repository_dispatch sang GitHub
  console.log(
    `Dispatching ${identifier} -> ${process.env.GITHUB_OWNER}/${process.env.GITHUB_REPO}` +
      ` (branch: ${clientPayload.branchName})`
  );
  const ghRes = await fetch(
    `https://api.github.com/repos/${process.env.GITHUB_OWNER}/${process.env.GITHUB_REPO}/dispatches`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
        Accept: "application/vnd.github+json",
        "User-Agent": "linear-claude-relay",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        event_type: "linear-agent",
        client_payload: clientPayload,
      }),
    }
  );

  if (!ghRes.ok) {
    const errText = await ghRes.text();
    console.error("GitHub dispatch failed:", ghRes.status, errText);
    return respond(502, `GitHub dispatch failed: ${ghRes.status}`);
  }

  console.log(`Dispatched ${identifier} -> ${clientPayload.branchName}`);
  return respond(200, "Dispatched");
};

function respond(statusCode, body) {
  return { statusCode, body };
}

function verifySignature(rawBody, signatureHex, secret) {
  if (!signatureHex || !secret) return false;
  const expected = createHmac("sha256", secret).update(rawBody, "utf8").digest("hex");
  const a = Buffer.from(expected);
  const b = Buffer.from(signatureHex);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}
