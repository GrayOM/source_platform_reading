import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import clsx from "clsx";
import { ChevronDown, ChevronRight, ExternalLink, FileText, Shield } from "lucide-react";
import { useState } from "react";
import { useParams } from "react-router-dom";
import { Badge, Card, CodeBlock, EmptyState, PageHeader, PageShell, Select } from "../components/ui";
import { getFindings, updateFinding } from "../lib/api";

const severities = ["critical", "high", "medium", "low", "info"] as const;

const STATUS_LABELS = {
  new: "New",
  confirmed: "Confirmed",
  false_positive: "False Positive",
  out_of_scope: "Out of Scope",
  accepted: "Accepted",
};

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <h4 className="mb-2 text-xs font-semibold uppercase tracking-normal text-slate-500">{title}</h4>
      {children}
    </section>
  );
}

function FindingCard({ finding }: { finding: any }) {
  const [expanded, setExpanded] = useState(false);
  const qc = useQueryClient();
  const { scanId } = useParams();

  const updateMutation = useMutation({
    mutationFn: (data: object) => updateFinding(finding.id, data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["findings", scanId] }),
  });

  const poc = finding.poc && Object.keys(finding.poc).length > 0 ? JSON.stringify(finding.poc, null, 2) : "";
  const evidence = finding.evidence && Object.keys(finding.evidence).length > 0 ? JSON.stringify(finding.evidence, null, 2) : "";

  return (
    <Card className="overflow-hidden transition-colors hover:border-slate-700">
      <button className="grid w-full gap-3 p-4 text-left md:grid-cols-[auto_1fr_auto_auto] md:items-center" onClick={() => setExpanded((value) => !value)}>
        <Badge tone={finding.severity}>{finding.severity}</Badge>
        <div className="min-w-0">
          <div className="truncate text-sm font-semibold text-white">{finding.title}</div>
          <div className="mt-1 flex flex-wrap gap-2 text-xs text-slate-500">
            <span>{finding.vulnerability_type}</span>
            <span>·</span>
            <span>{finding.agent_name}</span>
            {finding.affected_url && (
              <>
                <span>·</span>
                <span className="max-w-full truncate md:max-w-xs">{finding.affected_url}</span>
              </>
            )}
          </div>
        </div>
        <span className="rounded-md border border-slate-800 bg-slate-950/70 px-2 py-1 text-xs font-medium text-slate-300">
          {STATUS_LABELS[finding.status as keyof typeof STATUS_LABELS] ?? finding.status}
        </span>
        {expanded ? <ChevronDown className="h-4 w-4 text-slate-500" /> : <ChevronRight className="h-4 w-4 text-slate-500" />}
      </button>

      {expanded && (
        <div className="space-y-5 border-t border-slate-800 p-5">
          <div className="grid gap-3 sm:grid-cols-3">
            {[
              ["CWE", finding.cwe_id ? `CWE-${finding.cwe_id}` : "N/A"],
              ["CVSS", finding.cvss_score?.toFixed(1) ?? "N/A"],
              ["OWASP", finding.owasp_category ?? "N/A"],
            ].map(([key, value]) => (
              <div key={key} className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                <span className="block text-xs text-slate-500">{key}</span>
                <span className="mt-1 block break-words font-mono text-sm text-white">{value}</span>
              </div>
            ))}
          </div>

          {finding.affected_url && (
            <Section title="Affected URL">
              <div className="flex gap-2 rounded-lg border border-slate-800 bg-slate-950/50 p-3 text-xs text-slate-300">
                <ExternalLink className="mt-0.5 h-3.5 w-3.5 flex-shrink-0 text-slate-500" />
                <code className="break-all">{finding.affected_url}</code>
              </div>
            </Section>
          )}

          <Section title="Description">
            <p className="whitespace-pre-wrap break-words text-sm leading-6 text-slate-300">{finding.description}</p>
          </Section>

          {(finding.code_snippet || finding.evidence?.code_snippet) && (
            <Section title="Code snippet">
              <CodeBlock tone="green">{finding.code_snippet || finding.evidence.code_snippet}</CodeBlock>
            </Section>
          )}

          {evidence && (
            <Section title="Evidence">
              <CodeBlock>{evidence}</CodeBlock>
            </Section>
          )}

          {poc && (
            <Section title="Proof of concept">
              <CodeBlock tone="blue">{poc}</CodeBlock>
            </Section>
          )}

          {finding.reproduction_steps?.length > 0 && (
            <Section title="Reproduction steps">
              <ol className="space-y-2 text-sm text-slate-300">
                {finding.reproduction_steps.map((step: string, index: number) => (
                  <li key={index} className="flex gap-3">
                    <span className="flex h-6 w-6 flex-shrink-0 items-center justify-center rounded-md bg-slate-800 text-xs font-semibold text-slate-300">{index + 1}</span>
                    <span className="min-w-0 break-words leading-6">{step}</span>
                  </li>
                ))}
              </ol>
            </Section>
          )}

          {finding.recommendation && (
            <Section title="Recommendation">
              <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-4 text-sm leading-6 text-emerald-100">
                {finding.recommendation}
              </div>
            </Section>
          )}

          <div className="max-w-xs">
            <Section title="Review status">
              <Select value={finding.status} onChange={(e) => updateMutation.mutate({ status: e.target.value })} disabled={updateMutation.isPending}>
                {Object.entries(STATUS_LABELS).map(([key, value]) => (
                  <option key={key} value={key}>
                    {value}
                  </option>
                ))}
              </Select>
            </Section>
          </div>
        </div>
      )}
    </Card>
  );
}

export function Findings() {
  const { scanId } = useParams<{ scanId: string }>();
  const [severityFilter, setSeverityFilter] = useState<string>("");

  const { data: findings = [], isLoading } = useQuery({
    queryKey: ["findings", scanId, severityFilter],
    queryFn: () => getFindings(scanId, severityFilter || undefined),
  });

  const counts = findings.reduce((acc: Record<string, number>, finding: any) => {
    acc[finding.severity] = (acc[finding.severity] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <PageShell className="max-w-6xl">
      <PageHeader
        title="Findings"
        description="Review detected candidates, evidence, proof of concept details, reproduction steps, and remediation guidance."
      />

      <Card className="mb-5 p-3">
        <div className="flex flex-wrap gap-2">
          <button
            onClick={() => setSeverityFilter("")}
            className={clsx("rounded-lg px-3 py-2 text-xs font-semibold transition-colors", severityFilter === "" ? "bg-emerald-500 text-slate-950" : "bg-slate-950/60 text-slate-400 hover:text-white")}
          >
            All ({findings.length})
          </button>
          {severities.map((severity) => (
            <button
              key={severity}
              onClick={() => setSeverityFilter(severity)}
              className={clsx("rounded-lg px-3 py-2 text-xs font-semibold uppercase transition-colors", severityFilter === severity ? "bg-emerald-500 text-slate-950" : "bg-slate-950/60 text-slate-400 hover:text-white")}
            >
              {severity} {counts[severity] ? `(${counts[severity]})` : ""}
            </button>
          ))}
        </div>
      </Card>

      {isLoading ? (
        <Card className="p-8 text-sm text-slate-500">Loading findings...</Card>
      ) : findings.length === 0 ? (
        <EmptyState
          icon={<Shield className="h-10 w-10" />}
          title="No findings found"
          description="No findings match the current filter. Completed clean scans can still generate reports with collection summaries."
          action={<FileText className="h-5 w-5 text-slate-600" />}
        />
      ) : (
        <div className="space-y-3">
          {findings.map((finding: any) => (
            <FindingCard key={finding.id} finding={finding} />
          ))}
        </div>
      )}
    </PageShell>
  );
}
