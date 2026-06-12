import { useState } from "react";
import { useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { ChevronDown, ChevronRight, Shield, ExternalLink } from "lucide-react";
import clsx from "clsx";
import { getFindings, updateFinding } from "../lib/api";

const SEV_CONFIG = {
  critical: { bg: "bg-red-900/30",   border: "border-red-800",   badge: "bg-red-500",      text: "CRITICAL" },
  high:     { bg: "bg-orange-900/20", border: "border-orange-800", badge: "bg-orange-500",   text: "HIGH" },
  medium:   { bg: "bg-yellow-900/20", border: "border-yellow-800", badge: "bg-yellow-500 text-black", text: "MEDIUM" },
  low:      { bg: "bg-green-900/20",  border: "border-green-800",  badge: "bg-green-600",    text: "LOW" },
  info:     { bg: "bg-blue-900/20",   border: "border-blue-800",   badge: "bg-blue-600",     text: "INFO" },
};

const STATUS_LABELS = {
  new: "New",
  confirmed: "Confirmed",
  false_positive: "False Positive",
  out_of_scope: "Out of Scope",
  accepted: "Accepted",
};

function FindingCard({ finding }: { finding: any }) {
  const [expanded, setExpanded] = useState(false);
  const qc = useQueryClient();
  const { scanId } = useParams();

  const updateMutation = useMutation({
    mutationFn: (data: object) => updateFinding(finding.id, data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["findings", scanId] }),
  });

  const cfg = SEV_CONFIG[finding.severity as keyof typeof SEV_CONFIG] ?? SEV_CONFIG.info;

  return (
    <div className={clsx("border rounded-xl overflow-hidden", cfg.border, cfg.bg)}>
      <button
        className="w-full flex items-center gap-3 p-4 text-left hover:bg-white/5 transition-colors"
        onClick={() => setExpanded((e) => !e)}
      >
        <span className={clsx("text-xs font-bold px-2 py-1 rounded text-white shrink-0", cfg.badge)}>
          {cfg.text}
        </span>
        <span className="flex-1 text-sm font-medium text-white">{finding.title}</span>
        <span className="text-xs text-gray-500 shrink-0">{finding.agent_name}</span>
        {expanded ? <ChevronDown className="w-4 h-4 text-gray-500" /> : <ChevronRight className="w-4 h-4 text-gray-500" />}
      </button>

      {expanded && (
        <div className="p-5 pt-0 space-y-4 border-t border-white/10">
          <div className="grid grid-cols-3 gap-4 text-xs">
            {[
              ["CWE", finding.cwe_id ? `CWE-${finding.cwe_id}` : "N/A"],
              ["CVSS", finding.cvss_score?.toFixed(1) ?? "N/A"],
              ["OWASP", finding.owasp_category ?? "N/A"],
            ].map(([k, v]) => (
              <div key={k}>
                <span className="text-gray-500 block">{k}</span>
                <span className="text-white font-mono">{v}</span>
              </div>
            ))}
          </div>

          {finding.affected_url && (
            <div className="flex items-center gap-2 text-xs">
              <ExternalLink className="w-3.5 h-3.5 text-gray-500 shrink-0" />
              <code className="text-gray-300 break-all">{finding.affected_url}</code>
            </div>
          )}

          <div>
            <h4 className="text-xs font-semibold text-gray-400 uppercase mb-2">Description</h4>
            <p className="text-sm text-gray-300 whitespace-pre-wrap">{finding.description}</p>
          </div>

          {finding.evidence?.code_snippet && (
            <div>
              <h4 className="text-xs font-semibold text-gray-400 uppercase mb-2">Evidence</h4>
              <pre className="bg-gray-950 p-3 rounded-lg text-xs text-green-300 overflow-x-auto whitespace-pre-wrap">
                {finding.evidence.code_snippet}
              </pre>
            </div>
          )}

          {finding.recommendation && (
            <div className="bg-emerald-900/20 border border-emerald-800 rounded-lg p-3">
              <h4 className="text-xs font-semibold text-emerald-400 uppercase mb-1">Recommendation</h4>
              <p className="text-sm text-gray-300">{finding.recommendation}</p>
            </div>
          )}

          <div className="flex items-center gap-3 pt-2">
            <span className="text-xs text-gray-500">Status:</span>
            <select
              value={finding.status}
              onChange={(e) => updateMutation.mutate({ status: e.target.value })}
              className="text-xs bg-gray-800 border border-gray-700 rounded px-2 py-1 text-white focus:outline-none"
            >
              {Object.entries(STATUS_LABELS).map(([k, v]) => (
                <option key={k} value={k}>{v}</option>
              ))}
            </select>
          </div>
        </div>
      )}
    </div>
  );
}

export function Findings() {
  const { scanId } = useParams<{ scanId: string }>();
  const [severityFilter, setSeverityFilter] = useState<string>("");

  const { data: findings = [], isLoading } = useQuery({
    queryKey: ["findings", scanId, severityFilter],
    queryFn: () => getFindings(scanId, severityFilter || undefined),
  });

  const counts = findings.reduce((acc: Record<string, number>, f: any) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  return (
    <div className="p-8 max-w-4xl mx-auto">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white">Findings</h1>
          <p className="text-sm text-gray-500 mt-1">{findings.length} total</p>
        </div>
        <div className="flex gap-2">
          {["", "critical", "high", "medium", "low", "info"].map((sev) => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={clsx(
                "px-3 py-1.5 rounded-lg text-xs font-medium transition-colors",
                severityFilter === sev
                  ? "bg-emerald-500 text-black"
                  : "bg-gray-800 text-gray-400 hover:text-white"
              )}
            >
              {sev || "All"} {sev && counts[sev] ? `(${counts[sev]})` : ""}
            </button>
          ))}
        </div>
      </div>

      {isLoading ? (
        <div className="text-center py-16 text-gray-500">Loading findings...</div>
      ) : findings.length === 0 ? (
        <div className="text-center py-16 text-gray-500">
          <Shield className="w-10 h-10 mx-auto mb-3 opacity-30 text-emerald-400" />
          <p>No findings found.</p>
        </div>
      ) : (
        <div className="space-y-3">
          {findings.map((f: any) => <FindingCard key={f.id} finding={f} />)}
        </div>
      )}
    </div>
  );
}
