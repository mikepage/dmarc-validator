import { define } from "../../utils.ts";

interface DmarcTag {
  tag: string;
  value: string;
  description: string;
}

const tagDescriptions: Record<string, (value: string) => string> = {
  v: (value) => `DMARC version: ${value}`,
  p: (value) => {
    const policies: Record<string, string> = {
      none: "No action taken on failing emails (monitoring only)",
      quarantine: "Failing emails should be treated as suspicious (e.g., moved to spam)",
      reject: "Failing emails should be rejected outright",
    };
    return policies[value] || `Policy: ${value}`;
  },
  sp: (value) => {
    const policies: Record<string, string> = {
      none: "No action for subdomains",
      quarantine: "Quarantine failing emails from subdomains",
      reject: "Reject failing emails from subdomains",
    };
    return `Subdomain policy: ${policies[value] || value}`;
  },
  rua: (value) => `Aggregate reports sent to: ${value}`,
  ruf: (value) => `Forensic reports sent to: ${value}`,
  pct: (value) => `Policy applies to ${value}% of failing emails`,
  adkim: (value) =>
    value === "s"
      ? "DKIM alignment: Strict (exact domain match required)"
      : "DKIM alignment: Relaxed (organizational domain match allowed)",
  aspf: (value) =>
    value === "s"
      ? "SPF alignment: Strict (exact domain match required)"
      : "SPF alignment: Relaxed (organizational domain match allowed)",
  fo: (value) => {
    const options: Record<string, string> = {
      "0": "Generate failure report if all mechanisms fail",
      "1": "Generate failure report if any mechanism fails",
      d: "Generate failure report on DKIM failure",
      s: "Generate failure report on SPF failure",
    };
    return `Failure reporting: ${options[value] || value}`;
  },
  rf: (value) => `Report format: ${value}`,
  ri: (value) => `Report interval: ${value} seconds (${Math.round(parseInt(value) / 3600)} hours)`,
};

function parseDmarcRecord(record: string): DmarcTag[] {
  const tags: DmarcTag[] = [];
  const parts = record.split(";").map((p) => p.trim()).filter(Boolean);

  for (const part of parts) {
    const [tag, ...valueParts] = part.split("=");
    const value = valueParts.join("=").trim();
    const tagName = tag.trim().toLowerCase();

    const descriptionFn = tagDescriptions[tagName];
    const description = descriptionFn
      ? descriptionFn(value)
      : `${tagName}: ${value}`;

    tags.push({
      tag: tagName,
      value,
      description,
    });
  }

  return tags;
}

function getPolicyDescription(policy: string): string {
  switch (policy) {
    case "reject":
      return "This domain has a strict DMARC policy. Emails that fail DMARC authentication will be rejected by receiving mail servers. This is the strongest protection against email spoofing.";
    case "quarantine":
      return "This domain has a moderate DMARC policy. Emails that fail DMARC authentication may be treated as suspicious and placed in spam/junk folders.";
    case "none":
      return "This domain has a monitoring-only DMARC policy. No action is taken on failing emails, but reports may be collected. This provides no protection against spoofing.";
    default:
      return "Unknown policy type.";
  }
}

export const handler = define.handlers({
  async GET(ctx) {
    const url = new URL(ctx.req.url);
    const domain = url.searchParams.get("domain");

    if (!domain) {
      return Response.json(
        { success: false, error: "Domain is required" },
        { status: 400 }
      );
    }

    const cleanDomain = domain.replace(/^_dmarc\./, "").replace(/^https?:\/\//, "").replace(/\/.*$/, "");
    const dmarcDomain = `_dmarc.${cleanDomain}`;

    try {
      const startTime = performance.now();

      const records = await Deno.resolveDns(dmarcDomain, "TXT");

      const endTime = performance.now();
      const queryTime = Math.round(endTime - startTime);

      const dmarcRecord = records
        .map((r) => (Array.isArray(r) ? r.join("") : r))
        .find((r) => r.toLowerCase().startsWith("v=dmarc1"));

      if (!dmarcRecord) {
        return Response.json(
          { success: false, error: `No DMARC record found for ${cleanDomain}` },
          { status: 404 }
        );
      }

      const tags = parseDmarcRecord(dmarcRecord);
      const policyTag = tags.find((t) => t.tag === "p");
      const policy = policyTag?.value || "none";

      return Response.json({
        success: true,
        domain: cleanDomain,
        record: dmarcRecord,
        tags,
        policy,
        policyDescription: getPolicyDescription(policy),
        queryTime,
      });
    } catch (err) {
      const errorMessage =
        err instanceof Error ? err.message : "DMARC lookup failed";

      if (errorMessage.includes("no record")) {
        return Response.json(
          { success: false, error: `No DMARC record found for ${cleanDomain}. The domain may not have DMARC configured.` },
          { status: 404 }
        );
      }

      return Response.json(
        { success: false, error: errorMessage },
        { status: 500 }
      );
    }
  },
});
