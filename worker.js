/**
 * Linear -> GitHub relay (Cloudflare Worker)
 *
 * Nhan webhook Issue tu Linear, verify chu ky HMAC, kiem tra label
 * "ai-agent" vua duoc GAN VAO (khong phai co san), roi ban
 * repository_dispatch sang GitHub de trigger workflow linear-agent.yml.
 *
 * Secrets can set (wrangler secret put <NAME>):
 *   LINEAR_WEBHOOK_SECRET  - signing secret cua webhook trong Linear
 *   GITHUB_TOKEN           - fine-grained PAT, quyen: Contents R/W tren repo
 * Vars (wrangler.toml):
 *   GITHUB_OWNER, GITHUB_REPO, TRIGGER_LABEL (mac dinh "ai-agent")
 */

export default {
  async fetch(request, env) {
    if (request.method !== "POST") {
      return new Response("Method not allowed", { status: 405 });
    }

    const rawBody = await request.text();

    // 1. Verify chu ky: Linear gui HMAC-SHA256(rawBody) hex trong header
    const signature = request.headers.get("linear-signature") || "";
    const valid = await verifySignature(rawBody, signature, env.LINEAR_WEBHOOK_SECRET);
    if (!valid) {
      return new Response("Invalid signature", { status: 401 });
    }

    const payload = JSON.parse(rawBody);

    // 2. Chi quan tam Issue create/update
    if (payload.type !== "Issue" || !["create", "update"].includes(payload.action)) {
      return new Response("Ignored: not an issue event", { status: 200 });
    }

    const data = payload.data || {};
    const triggerLabel = (env.TRIGGER_LABEL || "ai-agent").toLowerCase();

    // 3. Kiem tra label hien tai co "ai-agent" khong
    const labels = (data.labels || []).map((l) => (l.name || "").toLowerCase());
    if (!labels.includes(triggerLabel)) {
      return new Response("Ignored: trigger label not present", { status: 200 });
    }

    // 4. Chong ban trung: voi action=update, chi fire khi label VUA duoc them
    //    (updatedFrom.labelIds ton tai nghia la labelIds vua thay doi)
    if (payload.action === "update" && !payload.updatedFrom?.labelIds) {
      return new Response("Ignored: label set unchanged", { status: 200 });
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
    const ghRes = await fetch(
      `https://api.github.com/repos/${env.GITHUB_OWNER}/${env.GITHUB_REPO}/dispatches`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${env.GITHUB_TOKEN}`,
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
      return new Response(`GitHub dispatch failed: ${ghRes.status}`, { status: 502 });
    }

    console.log(`Dispatched ${identifier} -> ${clientPayload.branchName}`);
    return new Response("Dispatched", { status: 200 });
  },
};

async function verifySignature(rawBody, signatureHex, secret) {
  if (!signatureHex || !secret) return false;
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const mac = await crypto.subtle.sign("HMAC", key, enc.encode(rawBody));
  const expected = [...new Uint8Array(mac)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  // So sanh timing-safe don gian
  if (expected.length !== signatureHex.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) {
    diff |= expected.charCodeAt(i) ^ signatureHex.charCodeAt(i);
  }
  return diff === 0;
}
