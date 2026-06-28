import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { formatDistanceToNow } from "date-fns";
import { AlertTriangle, Camera, CheckCircle, Code2, FileText, GitCompareArrows, Globe, Layers, Loader2, Radio, Route, ShieldCheck, XCircle } from "lucide-react";
import { useEffect, useState } from "react";
import toast from "react-hot-toast";
import { Link, useParams } from "react-router-dom";
import { Badge, Button, Card, EmptyState, PageHeader, PageShell, Select } from "../components/ui";
import { useScanProgress } from "../hooks/useScanProgress";
import { compareScans, generateReport, getDiffCandidates, getScan, getScanArtifacts } from "../lib/api";

const STATUS_CONFIG: Record<string, { tone: string; icon: React.ReactNode; label: string; description: string }> = {
  pending: { tone: "neutral", icon: <Loader2 className="h-4 w-4" />, label: "Pending", description: "Queued and waiting for a worker." },
  authenticating: { tone: "medium", icon: <Loader2 className="h-4 w-4 animate-spin" />, label: "Authenticating", description: "Waiting for browser session capture." },
  crawling: { tone: "info", icon: <Globe className="h-4 w-4 animate-pulse" />, label: "Crawling", description: "Collecting pages, resources, and browser traffic." },
  analyzing: { tone: "info", icon: <Loader2 className="h-4 w-4 animate-spin" />, label: "Analyzing", description: "Running deterministic analyzers and optional AI round2." },
  reporting: { tone: "info", icon: <FileText className="h-4 w-4 animate-pulse" />, label: "Reporting", description: "Generating report artifacts." },
  completed: { tone: "low", icon: <CheckCircle className="h-4 w-4" />, label: "Completed", description: "Scan finished and results are ready." },
  failed: { tone: "critical", icon: <XCircle className="h-4 w-4" />, label: "Failed", description: "Scan stopped before completion." },
  cancelled: { tone: "neutral", icon: <XCircle className="h-4 w-4" />, label: "Cancelled", description: "Scan was cancelled." },
};

export function ScanDetail() {
  const { scanId } = useParams<{ scanId: string }>();
  const qc = useQueryClient();
  const [compareScanId, setCompareScanId] = useState("");
  const [diffResult, setDiffResult] = useState<any>(null);

  const { data: scan, isLoading } = useQuery({
    queryKey: ["scan", scanId],
    queryFn: () => getScan(scanId!),
    refetchInterval: (query) => {
      const data = query.state.data as any;
      const active = ["pending", "crawling", "analyzing", "authenticating", "reporting"];
      return data && active.includes(data.status) ? 3000 : false;
    },
  });

  const active = scan && ["crawling", "analyzing", "authenticating", "reporting"].includes(scan.status);
  const wsProgress = useScanProgress(scanId, Boolean(active));

  const { data: diffCandidates = [] } = useQuery({
    queryKey: ["diff-candidates", scanId],
    queryFn: () => getDiffCandidates(scanId!),
    enabled: Boolean(scanId && scan?.status === "completed"),
  });

  const { data: artifacts = [] } = useQuery({
    queryKey: ["scan-artifacts", scanId],
    queryFn: () => getScanArtifacts(scanId!),
    enabled: Boolean(scanId && scan?.status === "completed"),
  });

  const compareMutation = useMutation({
    mutationFn: () => compareScans(scanId!, compareScanId),
    onSuccess: (data) => {
      setDiffResult(data);
      toast.success("Comparison complete");
    },
    onError: (err: any) => toast.error(err.response?.data?.detail ?? "Failed to compare scans"),
  });

  const comparisonReportMutation = useMutation({
    mutationFn: () => generateReport(scanId!, "html", "full", compareScanId),
    onSuccess: () => toast.success("Comparison report generation started"),
    onError: (err: any) => toast.error(err.response?.data?.detail ?? "Failed to generate comparison report"),
  });

  useEffect(() => {
    if (wsProgress) {
      qc.setQueryData(["scan", scanId], (old: any) =>
        old
          ? {
              ...old,
              progress: wsProgress.progress,
              status: wsProgress.phase === "completed" ? "completed" : old.status,
              pages_discovered: wsProgress.pages_discovered ?? old.pages_discovered,
              resources_collected: wsProgress.resources_collected ?? old.resources_collected,
              findings_count: wsProgress.findings_count ?? old.findings_count,
            }
          : old
      );
    }
  }, [wsProgress, scanId, qc]);

  if (isLoading) {
    return (
      <PageShell>
        <Card className="p-8 text-sm text-slate-500">Loading scan details...</Card>
      </PageShell>
    );
  }

  if (!scan) {
    return (
      <PageShell>
        <EmptyState icon={<FileText className="h-10 w-10" />} title="Scan not found" description="The scan may have been deleted or you may not have access to it." />
      </PageShell>
    );
  }

  const status = STATUS_CONFIG[scan.status] ?? STATUS_CONFIG.pending;
  const progress = Math.max(0, Math.min(100, scan.progress ?? 0));

  return (
    <PageShell className="max-w-5xl">
      <PageHeader
        title="Scan detail"
        description={status.description}
        action={
          <div className="flex flex-wrap gap-2">
            {scan.status === "completed" && (
              <>
                <Link to={`/scans/${scanId}/findings`} className="inline-flex items-center gap-2 rounded-lg border border-slate-700 bg-slate-800 px-4 py-2.5 text-sm font-semibold text-white hover:bg-slate-700">
                  <AlertTriangle className="h-4 w-4 text-orange-300" />
                  View Findings
                </Link>
                <Link to={`/scans/${scanId}/reports`} className="inline-flex items-center gap-2 rounded-lg bg-emerald-500 px-4 py-2.5 text-sm font-semibold text-slate-950 hover:bg-emerald-400">
                  <FileText className="h-4 w-4" />
                  Generate Report
                </Link>
              </>
            )}
          </div>
        }
      />

      <Card className="mb-6 p-5">
        <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
          <div className="min-w-0">
            <div className="mb-3 flex items-center gap-2">
              <Badge tone={status.tone}>
                <span className="mr-1.5">{status.icon}</span>
                {status.label}
              </Badge>
              <span className="text-xs text-slate-500">
                Started {formatDistanceToNow(new Date(scan.started_at ?? scan.created_at), { addSuffix: true })}
              </span>
            </div>
            <h2 className="break-words text-lg font-semibold text-white">{scan.target_url}</h2>
            <p className="mt-1 break-all font-mono text-xs text-slate-600">{scan.id}</p>
          </div>
          <div className="min-w-36 rounded-lg border border-slate-800 bg-slate-950/60 p-3">
            <div className="text-xs text-slate-500">Progress</div>
            <div className="mt-1 text-2xl font-semibold text-white">{progress}%</div>
          </div>
        </div>
      </Card>

      <Card className="mb-6 p-5">
        <div className="mb-3 flex items-center justify-between gap-3">
          <div className="flex min-w-0 items-center gap-2 text-sm text-slate-300">
            <Radio className="h-4 w-4 flex-shrink-0 text-emerald-300" />
            <span className="truncate">{wsProgress?.message ?? (active ? `${status.label}...` : "Latest scan state")}</span>
          </div>
          <span className="text-sm font-semibold text-white">{progress}%</span>
        </div>
        <div className="h-2 overflow-hidden rounded-full bg-slate-800">
          <div className="h-full rounded-full bg-emerald-400 transition-all duration-500" style={{ width: `${progress}%` }} />
        </div>
      </Card>

      {scan.error_message && (
        <div className="mb-6 rounded-lg border border-red-900/70 bg-red-950/40 p-4 text-sm leading-6 text-red-200">
          <strong className="text-red-100">Scan error:</strong> {scan.error_message}
        </div>
      )}

      <div className="grid gap-4 sm:grid-cols-3">
        {[
          { icon: Globe, label: "Pages", value: scan.pages_discovered, color: "text-sky-300" },
          { icon: Layers, label: "Resources", value: scan.resources_collected, color: "text-blue-300" },
          { icon: AlertTriangle, label: "Findings", value: scan.findings_count, color: scan.findings_count > 0 ? "text-orange-300" : "text-emerald-300" },
        ].map(({ icon: Icon, label, value, color }) => (
          <Card key={label} className="p-5">
            <Icon className={`mb-3 h-5 w-5 ${color}`} />
            <div className={`text-3xl font-semibold ${color}`}>{value ?? 0}</div>
            <div className="mt-1 text-sm text-slate-500">{label}</div>
          </Card>
        ))}
      </div>

      {scan.status === "completed" && (
        <Card className="mt-6 p-5">
          <div className="mb-4 flex items-center gap-2">
            <FileText className="h-4 w-4 text-emerald-300" />
            <h2 className="font-semibold text-white">Artifact Summary</h2>
          </div>
          <div className="grid gap-3 sm:grid-cols-5">
            {[
              [FileText, "Total", artifacts.length],
              [Camera, "Screenshots", artifacts.filter((a: any) => a.artifact_type === "screenshot").length],
              [Code2, "Source files", artifacts.filter((a: any) => a.artifact_type === "source_file" || a.artifact_type === "source_map").length],
              [Route, "API flows", artifacts.filter((a: any) => a.artifact_type === "api_flow").length],
              [ShieldCheck, "Authenticated", artifacts.filter((a: any) => a.auth_context === "authenticated").length],
            ].map(([Icon, label, value]: any) => (
              <div key={label} className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
                <Icon className="mb-2 h-4 w-4 text-slate-400" />
                <div className="text-xl font-semibold text-white">{value}</div>
                <div className="text-xs text-slate-500">{label}</div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {scan.status === "completed" && diffCandidates.length > 0 && (
        <Card className="mt-6 p-5">
          <div className="mb-4 flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
            <div>
              <h2 className="font-semibold text-white">Cross-scan compare</h2>
              <p className="mt-1 text-sm text-slate-500">Compare this scan against another completed scan from the same project and origin.</p>
            </div>
            {diffResult && (
              <Button onClick={() => comparisonReportMutation.mutate()} disabled={comparisonReportMutation.isPending || !compareScanId}>
                {comparisonReportMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileText className="h-4 w-4" />}
                Generate comparison report
              </Button>
            )}
          </div>
          <div className="grid gap-3 md:grid-cols-[1fr_auto]">
            <Select value={compareScanId} onChange={(e) => { setCompareScanId(e.target.value); setDiffResult(null); }}>
              <option value="">Select comparison scan</option>
              {diffCandidates.map((candidate: any) => (
                <option key={candidate.id} value={candidate.id}>
                  {candidate.auth_method} · {candidate.target_url} · {candidate.id.slice(0, 8)}
                </option>
              ))}
            </Select>
            <Button variant="secondary" onClick={() => compareMutation.mutate()} disabled={!compareScanId || compareMutation.isPending}>
              {compareMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <GitCompareArrows className="h-4 w-4" />}
              Compare
            </Button>
          </div>
          {diffResult && (
            <div className="mt-5 grid gap-3 sm:grid-cols-5">
              {[
                ["New pages", diffResult.new_pages_count],
                ["New resources", diffResult.new_resources_count],
                ["New APIs", diffResult.new_api_endpoints_count],
                ["New findings", diffResult.new_findings_count],
                ["High confidence", diffResult.high_confidence_new_findings_count],
              ].map(([label, value]) => (
                <div key={label} className="rounded-lg border border-slate-800 bg-slate-950/60 p-3">
                  <div className="text-lg font-semibold text-white">{value}</div>
                  <div className="text-xs text-slate-500">{label}</div>
                </div>
              ))}
            </div>
          )}
          {diffResult?.new_api_endpoints?.length > 0 && (
            <div className="mt-4">
              <div className="mb-2 text-sm font-medium text-slate-300">New authenticated API endpoints</div>
              <div className="space-y-2">
                {diffResult.new_api_endpoints.slice(0, 5).map((endpoint: any) => (
                  <div key={endpoint.endpoint} className="break-all rounded-lg border border-slate-800 bg-slate-950/40 p-3 font-mono text-xs text-slate-300">
                    {endpoint.endpoint}
                  </div>
                ))}
              </div>
            </div>
          )}
        </Card>
      )}
    </PageShell>
  );
}
