import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import clsx from "clsx";
import { ChevronDown, ChevronRight, ExternalLink, FileText, Shield } from "lucide-react";
import { useState } from "react";
import { useParams } from "react-router-dom";
import { Badge, Button, Card, CodeBlock, EmptyState, PageHeader, PageShell, Select, TextArea } from "../components/ui";
import { getFindingArtifacts, getFindings, updateFinding, updateFindingTriage } from "../lib/api";

const severities = ["critical", "high", "medium", "low", "info"] as const;
const triageFilters = [
  ["", "All"],
  ["candidate", "Candidate"],
  ["needs_review", "Needs Review"],
  ["verified", "Verified"],
  ["false_positive", "False Positive"],
  ["accepted_risk", "Accepted Risk"],
  ["fixed", "Fixed"],
] as const;
const recurrenceFilters = [
  ["", "All recurrence"],
  ["only_new", "New"],
  ["recurring", "Recurring"],
  ["previously_verified", "Previously verified"],
  ["previously_false_positive", "Previously false positive"],
] as const;

const STATUS_LABELS = {
  new: "New",
  confirmed: "Confirmed",
  false_positive: "False Positive",
  out_of_scope: "Out of Scope",
  accepted: "Accepted",
};

const TRIAGE_LABELS = {
  candidate: "Candidate",
  verified: "Verified",
  false_positive: "False Positive",
  accepted_risk: "Accepted Risk",
  fixed: "Fixed",
  needs_review: "Needs Review",
};

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section>
      <h4 className="mb-2 text-xs font-semibold uppercase tracking-normal text-slate-500">{title}</h4>
      {children}
    </section>
  );
}

function ArtifactList({ findingId, enabled }: { findingId: string; enabled: boolean }) {
  const { data: artifacts = [], isLoading } = useQuery({
    queryKey: ["finding-artifacts", findingId],
    queryFn: () => getFindingArtifacts(findingId),
    enabled,
  });

  if (isLoading) {
    return <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3 text-sm text-slate-500">Loading artifacts...</div>;
  }
  if (artifacts.length === 0) {
    return <div className="rounded-lg border border-slate-800 bg-slate-950/50 p-3 text-sm text-slate-500">No linked evidence artifacts.</div>;
  }

  return (
    <div className="space-y-3">
      {artifacts.map((artifact: any) => (
        <div key={artifact.id} className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <Badge tone="info">{artifact.artifact_type}</Badge>
            {artifact.auth_context && <Badge tone={artifact.auth_context === "authenticated" ? "low" : "neutral"}>{artifact.auth_context}</Badge>}
            {artifact.verification_required && <Badge tone="medium">verification required</Badge>}
          </div>
          <div className="text-sm font-semibold text-white">{artifact.title}</div>
          {artifact.description && <p className="mt-1 text-sm leading-6 text-slate-400">{artifact.description}</p>}
          <div className="mt-3 grid gap-2 text-xs sm:grid-cols-2">
            {[
              ["URL", artifact.url],
              ["Source path", artifact.file_path],
              ["Screenshot", artifact.screenshot_path],
              ["Hash", artifact.content_hash],
              ["HTTP", artifact.http_method || artifact.status_code ? `${artifact.http_method ?? ""} ${artifact.status_code ?? ""}`.trim() : null],
              ["Content type", artifact.content_type],
              ["Line range", artifact.line_start ? `${artifact.line_start}${artifact.line_end && artifact.line_end !== artifact.line_start ? `-${artifact.line_end}` : ""}` : null],
              ["Storage", artifact.storage_type || artifact.storage_key ? `${artifact.storage_type ?? ""} ${artifact.storage_key ?? ""}`.trim() : null],
            ].filter(([, value]) => Boolean(value)).map(([label, value]) => (
              <div key={label} className="min-w-0 rounded-md border border-slate-800 bg-slate-950/70 p-2">
                <span className="block text-slate-500">{label}</span>
                <code className="mt-1 block break-all text-slate-300">{value}</code>
              </div>
            ))}
          </div>
          {(artifact.redacted_body_preview || artifact.redacted_value) && (
            <div className="mt-3 max-h-56 overflow-auto rounded-md border border-slate-800 bg-slate-950 p-3 font-mono text-xs text-slate-300">
              <pre className="whitespace-pre-wrap break-words">{artifact.redacted_body_preview || artifact.redacted_value}</pre>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

function FindingCard({ finding }: { finding: any }) {
  const [expanded, setExpanded] = useState(false);
  const [triageStatus, setTriageStatus] = useState(finding.triage_status ?? "candidate");
  const [analystNote, setAnalystNote] = useState(finding.analyst_note ?? "");
  const [verificationNote, setVerificationNote] = useState(finding.verification_note ?? "");
  const qc = useQueryClient();
  const { scanId } = useParams();

  const updateMutation = useMutation({
    mutationFn: (data: object) => updateFinding(finding.id, data),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["findings", scanId] }),
  });
  const triageMutation = useMutation({
    mutationFn: () =>
      updateFindingTriage(finding.id, {
        triage_status: triageStatus,
        analyst_note: analystNote || null,
        verification_note: verificationNote || null,
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["findings", scanId] }),
  });

  const poc = finding.poc && Object.keys(finding.poc).length > 0 ? JSON.stringify(finding.poc, null, 2) : "";
  const evidence = finding.evidence && Object.keys(finding.evidence).length > 0 ? JSON.stringify(finding.evidence, null, 2) : "";
  const isRecurring = finding.duplicate_of_finding_id || (finding.recurrence_count ?? 1) > 1;
  const shortFingerprint = finding.fingerprint ? `${finding.fingerprint.slice(0, 16)}...${finding.fingerprint.slice(-8)}` : "N/A";

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
            <span>·</span>
            <span>{isRecurring ? "Recurring" : "New"}</span>
            <span>·</span>
            <span>{finding.artifact_count ?? 0} artifacts</span>
            {finding.affected_url && (
              <>
                <span>·</span>
                <span className="max-w-full truncate md:max-w-xs">{finding.affected_url}</span>
              </>
            )}
          </div>
        </div>
        <span className="rounded-md border border-slate-800 bg-slate-950/70 px-2 py-1 text-xs font-medium text-slate-300">
          {TRIAGE_LABELS[finding.triage_status as keyof typeof TRIAGE_LABELS] ?? "Candidate"}
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

          <div className="flex flex-wrap gap-2">
            <Badge tone={isRecurring ? "medium" : "info"}>{isRecurring ? "Recurring" : "New"}</Badge>
            {finding.previously_verified && <Badge tone="low">Previously verified</Badge>}
            {finding.previously_marked_false_positive && <Badge tone="neutral">Previously false positive</Badge>}
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

          <Section title="Fingerprint & recurrence">
            <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
              {[
                ["Fingerprint", shortFingerprint],
                ["Recurrence count", finding.recurrence_count ?? 1],
                ["Previous triage", finding.previous_triage_status ?? "N/A"],
                ["Previous finding", finding.previous_finding_id ?? "N/A"],
                ["First seen", finding.first_seen_at ? new Date(finding.first_seen_at).toLocaleString() : "N/A"],
                ["Last seen", finding.last_seen_at ? new Date(finding.last_seen_at).toLocaleString() : "N/A"],
              ].map(([key, value]) => (
                <div key={key} className="rounded-lg border border-slate-800 bg-slate-950/50 p-3">
                  <span className="block text-xs text-slate-500">{key}</span>
                  <span className="mt-1 block break-words font-mono text-xs text-white">{value}</span>
                </div>
              ))}
            </div>
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

          <Section title="Evidence artifacts">
            <ArtifactList findingId={finding.id} enabled={expanded} />
          </Section>

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

          <Section title="Triage">
            <div className="grid gap-3 rounded-lg border border-slate-800 bg-slate-950/40 p-4 lg:grid-cols-[220px_1fr]">
              <div className="space-y-3">
                <div>
                  <span className="mb-2 block text-xs font-semibold uppercase tracking-normal text-slate-500">Current status</span>
                  <Badge tone={triageStatus === "verified" ? "low" : triageStatus === "false_positive" ? "neutral" : "info"}>
                    {TRIAGE_LABELS[triageStatus as keyof typeof TRIAGE_LABELS] ?? triageStatus}
                  </Badge>
                </div>
                <Select value={triageStatus} onChange={(e) => setTriageStatus(e.target.value)} disabled={triageMutation.isPending}>
                  {Object.entries(TRIAGE_LABELS).map(([key, value]) => (
                    <option key={key} value={key}>
                      {value}
                    </option>
                  ))}
                </Select>
                <Button onClick={() => triageMutation.mutate()} disabled={triageMutation.isPending} className="w-full">
                  Save triage
                </Button>
                {triageMutation.isSuccess && <p className="text-xs text-emerald-300">Triage saved.</p>}
                {triageMutation.isError && <p className="text-xs text-red-300">Failed to save triage.</p>}
                <div className="text-xs leading-5 text-slate-500">
                  <div>Reviewed: {finding.reviewed_at ? new Date(finding.reviewed_at).toLocaleString() : "N/A"}</div>
                  <div className="break-all">Reviewer: {finding.reviewed_by ?? "N/A"}</div>
                </div>
              </div>
              <div className="grid gap-3">
                <label className="block">
                  <span className="mb-2 block text-xs font-semibold uppercase tracking-normal text-slate-500">Analyst note</span>
                  <TextArea value={analystNote} onChange={(e) => setAnalystNote(e.target.value)} rows={4} className="resize-y" />
                </label>
                <label className="block">
                  <span className="mb-2 block text-xs font-semibold uppercase tracking-normal text-slate-500">Verification note</span>
                  <TextArea value={verificationNote} onChange={(e) => setVerificationNote(e.target.value)} rows={4} className="resize-y" />
                </label>
              </div>
            </div>
          </Section>
        </div>
      )}
    </Card>
  );
}

export function Findings() {
  const { scanId } = useParams<{ scanId: string }>();
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [triageFilter, setTriageFilter] = useState<string>("");
  const [recurrenceFilter, setRecurrenceFilter] = useState<string>("");

  const { data: findings = [], isLoading } = useQuery({
    queryKey: ["findings", scanId, severityFilter, triageFilter, recurrenceFilter],
    queryFn: () => getFindings(scanId, severityFilter || undefined, triageFilter || undefined, recurrenceFilter || undefined),
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
        <div className="mt-3 flex flex-wrap gap-2 border-t border-slate-800 pt-3">
          {triageFilters.map(([value, label]) => (
            <button
              key={value || "all-triage"}
              onClick={() => setTriageFilter(value)}
              className={clsx("rounded-lg px-3 py-2 text-xs font-semibold transition-colors", triageFilter === value ? "bg-sky-400 text-slate-950" : "bg-slate-950/60 text-slate-400 hover:text-white")}
            >
              {label}
            </button>
          ))}
        </div>
        <div className="mt-3 flex flex-wrap gap-2 border-t border-slate-800 pt-3">
          {recurrenceFilters.map(([value, label]) => (
            <button
              key={value || "all-recurrence"}
              onClick={() => setRecurrenceFilter(value)}
              className={clsx("rounded-lg px-3 py-2 text-xs font-semibold transition-colors", recurrenceFilter === value ? "bg-amber-300 text-slate-950" : "bg-slate-950/60 text-slate-400 hover:text-white")}
            >
              {label}
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
