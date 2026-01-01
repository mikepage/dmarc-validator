import { useSignal } from "@preact/signals";
import { useEffect } from "preact/hooks";

interface DmarcTag {
  tag: string;
  value: string;
  description: string;
}

interface DmarcResult {
  domain: string;
  record: string;
  tags: DmarcTag[];
  policy: string;
  policyDescription: string;
  queryTime: number;
}

function parseHash(hash: string): string | null {
  const match = hash.match(/^#(.+?)\/?\s*$/);
  if (!match) return null;
  return match[1];
}

function updateHash(domain: string) {
  if (domain) {
    window.history.replaceState(null, "", `#${domain}`);
  } else {
    window.history.replaceState(null, "", window.location.pathname);
  }
}

export default function DmarcValidator() {
  const domain = useSignal("");
  const isLoading = useSignal(false);
  const result = useSignal<DmarcResult | null>(null);
  const error = useSignal<string | null>(null);
  const initialLoadDone = useSignal(false);

  const handleLookup = async () => {
    error.value = null;
    result.value = null;

    const domainValue = domain.value.trim();
    if (!domainValue) {
      error.value = "Please enter a domain name";
      return;
    }

    isLoading.value = true;

    try {
      const params = new URLSearchParams({ domain: domainValue });
      const response = await fetch(`/api/dmarc?${params}`);
      const data = await response.json();

      if (!data.success) {
        error.value = data.error || "DMARC lookup failed";
        return;
      }

      result.value = data;
    } catch {
      error.value = "Failed to perform DMARC lookup";
    } finally {
      isLoading.value = false;
    }
  };

  const handleClear = () => {
    domain.value = "";
    result.value = null;
    error.value = null;
    updateHash("");
  };

  useEffect(() => {
    const handleHashChange = () => {
      const parsed = parseHash(window.location.hash);
      if (parsed) {
        domain.value = parsed;
        if (!initialLoadDone.value) {
          initialLoadDone.value = true;
          handleLookup();
        }
      } else {
        initialLoadDone.value = true;
      }
    };

    handleHashChange();

    window.addEventListener("hashchange", handleHashChange);
    return () => window.removeEventListener("hashchange", handleHashChange);
  }, []);

  useEffect(() => {
    if (initialLoadDone.value) {
      updateHash(domain.value.trim());
    }
  }, [domain.value]);

  const getPolicyColor = (policy: string) => {
    switch (policy) {
      case "reject":
        return "bg-green-100 text-green-800 border-green-200";
      case "quarantine":
        return "bg-yellow-100 text-yellow-800 border-yellow-200";
      case "none":
        return "bg-red-100 text-red-800 border-red-200";
      default:
        return "bg-gray-100 text-gray-800 border-gray-200";
    }
  };

  return (
    <div class="w-full">
      {/* Input Section */}
      <div class="bg-white rounded-lg shadow p-6 mb-6">
        <h2 class="text-lg font-semibold text-gray-800 mb-4">DMARC Lookup</h2>

        <div class="mb-4">
          <label class="block text-sm font-medium text-gray-700 mb-1">
            Domain Name
          </label>
          <input
            type="text"
            value={domain.value}
            onInput={(e) =>
              (domain.value = (e.target as HTMLInputElement).value)
            }
            onKeyDown={(e) => {
              if (e.key === "Enter") handleLookup();
            }}
            placeholder="example.com"
            class="w-full px-3 py-2 border border-gray-300 rounded-md focus:ring-2 focus:ring-blue-500 focus:border-blue-500 font-mono text-sm"
          />
        </div>

        {/* Action Buttons */}
        <div class="flex flex-wrap gap-3">
          <button
            onClick={handleLookup}
            disabled={!domain.value.trim() || isLoading.value}
            class="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors font-medium"
          >
            {isLoading.value ? "Looking up..." : "Lookup DMARC"}
          </button>
          <button
            onClick={handleClear}
            class="px-4 py-2 bg-gray-200 text-gray-700 rounded-md hover:bg-gray-300 transition-colors"
          >
            Clear
          </button>
        </div>
      </div>

      {/* Error */}
      {error.value && (
        <div class="bg-red-50 border border-red-200 rounded-lg p-4 mb-6">
          <p class="text-red-600">{error.value}</p>
        </div>
      )}

      {/* Results */}
      {result.value && (
        <div class="space-y-6">
          {/* Policy Summary */}
          <div class="bg-white rounded-lg shadow p-6">
            <h3 class="text-lg font-semibold text-gray-800 mb-4">
              DMARC Policy for {result.value.domain}
            </h3>

            <div
              class={`inline-block px-4 py-2 rounded-md border font-medium mb-4 ${getPolicyColor(
                result.value.policy
              )}`}
            >
              Policy: {result.value.policy.toUpperCase()}
            </div>

            <p class="text-gray-700 mb-4">{result.value.policyDescription}</p>

            <div class="text-sm text-gray-500">
              Query Time: {result.value.queryTime}ms
            </div>
          </div>

          {/* Raw Record */}
          <div class="bg-white rounded-lg shadow p-6">
            <h3 class="text-lg font-semibold text-gray-800 mb-4">
              Raw DMARC Record
            </h3>
            <pre class="font-mono text-sm bg-gray-50 p-4 rounded-md break-all whitespace-pre-wrap border">
              {result.value.record}
            </pre>
          </div>

          {/* Tag Breakdown */}
          <div class="bg-white rounded-lg shadow p-6">
            <h3 class="text-lg font-semibold text-gray-800 mb-4">
              Record Breakdown
            </h3>
            <div class="space-y-3">
              {result.value.tags.map((tag, index) => (
                <div
                  key={index}
                  class="border border-gray-200 rounded-md p-4 bg-gray-50"
                >
                  <div class="flex items-start gap-4">
                    <div class="font-mono text-sm bg-blue-100 text-blue-800 px-2 py-1 rounded">
                      {tag.tag}={tag.value}
                    </div>
                    <div class="text-sm text-gray-700 flex-1">
                      {tag.description}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Reference Section */}
      <details class="bg-white rounded-lg shadow mt-6">
        <summary class="p-4 cursor-pointer font-medium text-gray-800 hover:bg-gray-50">
          DMARC Tag Reference
        </summary>
        <div class="p-4 pt-0 border-t">
          <table class="w-full text-sm">
            <thead>
              <tr class="text-left text-gray-500">
                <th class="pb-2">Tag</th>
                <th class="pb-2">Description</th>
                <th class="pb-2">Values</th>
              </tr>
            </thead>
            <tbody class="text-gray-700">
              <tr class="border-t border-gray-100">
                <td class="py-2 font-mono">v</td>
                <td class="py-2">Version</td>
                <td class="py-2">Must be "DMARC1"</td>
              </tr>
              <tr class="border-t border-gray-100">
                <td class="py-2 font-mono">p</td>
                <td class="py-2">Policy</td>
                <td class="py-2">none, quarantine, reject</td>
              </tr>
              <tr class="border-t border-gray-100">
                <td class="py-2 font-mono">sp</td>
                <td class="py-2">Subdomain Policy</td>
                <td class="py-2">none, quarantine, reject</td>
              </tr>
              <tr class="border-t border-gray-100">
                <td class="py-2 font-mono">rua</td>
                <td class="py-2">Aggregate Report URI</td>
                <td class="py-2">mailto:address</td>
              </tr>
              <tr class="border-t border-gray-100">
                <td class="py-2 font-mono">ruf</td>
                <td class="py-2">Forensic Report URI</td>
                <td class="py-2">mailto:address</td>
              </tr>
              <tr class="border-t border-gray-100">
                <td class="py-2 font-mono">pct</td>
                <td class="py-2">Percentage</td>
                <td class="py-2">0-100 (default 100)</td>
              </tr>
              <tr class="border-t border-gray-100">
                <td class="py-2 font-mono">adkim</td>
                <td class="py-2">DKIM Alignment</td>
                <td class="py-2">r (relaxed), s (strict)</td>
              </tr>
              <tr class="border-t border-gray-100">
                <td class="py-2 font-mono">aspf</td>
                <td class="py-2">SPF Alignment</td>
                <td class="py-2">r (relaxed), s (strict)</td>
              </tr>
              <tr class="border-t border-gray-100">
                <td class="py-2 font-mono">fo</td>
                <td class="py-2">Failure Reporting Options</td>
                <td class="py-2">0, 1, d, s</td>
              </tr>
              <tr class="border-t border-gray-100">
                <td class="py-2 font-mono">rf</td>
                <td class="py-2">Report Format</td>
                <td class="py-2">afrf (default)</td>
              </tr>
              <tr class="border-t border-gray-100">
                <td class="py-2 font-mono">ri</td>
                <td class="py-2">Report Interval</td>
                <td class="py-2">Seconds (default 86400)</td>
              </tr>
            </tbody>
          </table>
        </div>
      </details>
    </div>
  );
}
