import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { formatDistanceToNow } from "date-fns";
import { ChevronDown, ChevronRight, Download, FileJson, FileText, Info, Loader2, Plus } from "lucide-react";
import { useState } from "react";
import toast from "react-hot-toast";
import { useParams } from "react-router-dom";
import { Badge, Button, Card, EmptyState, Field, PageHeader, PageShell, Select, TextArea, TextInput } from "../components/ui";
import { downloadReport, generateReport, getDiffCandidates, getScanReports } from "../lib/api";

const FORMATS = [
  { value: "html", label: "HTML", desc: "Browser-friendly report" },
  { value: "markdown", label: "Markdown", desc: "PRs and documentation" },
  { value: "json", label: "JSON", desc: "Tooling and automation" },
  { value: "pdf", label: "PDF", desc: "Experimental; falls back to HTML" },
] as const;

const TYPES = ["full", "kisa", "owasp", "executive", "technical"] as const;
const TYPE_LABELS: Record<string, string> = {
  full: "Full Report",
  kisa: "KISA Format",
  owasp: "OWASP Top 10",
  executive: "Executive Summary",
  technical: "Technical Details",
};

const CLASSIFICATIONS = ["", "Public", "Internal", "Confidential", "Restricted"] as const;
const METADATA_DEFAULTS = {
  report_title: "",
  client_name: "",
  service_name: "",
  organization_name: "",
  author: "",
  reviewer: "",
  document_version: "",
  report_id: "",
  classification: "",
  assessment_start_date: "",
  assessment_end_date: "",
  assessment_scope: "",
  out_of_scope: "",
  methodology: "",
  limitations: "",
  contact: "",
  prepared_date: "",
  executive_summary_note: "",
  remediation_due_date: "",
  custom_notes: "",
};

function buildReportMetadata(values: typeof METADATA_DEFAULTS) {
  const metadata: Record<string, string | string[]> = {};
  Object.entries(values).forEach(([key, value]) => {
    const trimmed = value.trim();
    if (!trimmed) return;
    if (["out_of_scope", "methodology", "limitations"].includes(key)) {
      metadata[key] = trimmed.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    } else {
      metadata[key] = trimmed;
    }
  });
  return Object.keys(metadata).length > 0 ? metadata : undefined;
}

export function Reports() {
  const { scanId } = useParams<{ scanId: string }>();
  const qc = useQueryClient();
  const [format, setFormat] = useState<string>("html");
  const [type, setType] = useState<string>("full");
  const [compareScanId, setCompareScanId] = useState<string>("");
  const [downloadingId, setDownloadingId] = useState<string>("");
  const [metadataOpen, setMetadataOpen] = useState(false);
  const [metadata, setMetadata] = useState(METADATA_DEFAULTS);

  const { data: reports = [], isLoading } = useQuery({
    queryKey: ["reports", scanId],
    queryFn: () => getScanReports(scanId!),
    refetchInterval: (query) => {
      const data = query.state.data as any[] | undefined;
      return (data ?? []).some((report: any) => !report.file_path) ? 3000 : false;
    },
  });

  const { data: diffCandidates = [] } = useQuery({
    queryKey: ["diff-candidates", scanId],
    queryFn: () => getDiffCandidates(scanId!),
    enabled: Boolean(scanId),
  });

  const generateMutation = useMutation({
    mutationFn: () => generateReport(scanId!, format, type, compareScanId || undefined, buildReportMetadata(metadata)),
    onSuccess: () => {
      toast.success("Report generation started");
      qc.invalidateQueries({ queryKey: ["reports", scanId] });
    },
    onError: (err: any) => toast.error(err.response?.data?.detail ?? "Failed to generate report"),
  });

  const downloadMutation = useMutation({
    mutationFn: (reportId: string) => downloadReport(reportId),
    onMutate: (reportId) => setDownloadingId(reportId),
    onSuccess: () => toast.success("Report downloaded"),
    onError: (err: any) => toast.error(err.response?.data?.detail ?? "Download failed"),
    onSettled: () => setDownloadingId(""),
  });

  return (
    <PageShell className="max-w-5xl">
      <PageHeader title="Reports" description="Generate and download scan reports with findings, PoC, reproduction steps, and collection summaries." />

      <Card className="mb-6 p-5">
        <div className="mb-5">
          <h2 className="font-semibold text-white">Generate report</h2>
          <p className="mt-1 text-sm text-slate-500">HTML, Markdown, and JSON are the stable export formats. PDF uses HTML fallback if rendering fails.</p>
        </div>

        <div className="grid gap-5 lg:grid-cols-[1fr_260px]">
          <div>
            <div className="mb-2 text-sm font-medium text-slate-300">Format</div>
            <div className="grid gap-3 sm:grid-cols-2">
              {FORMATS.map((item) => (
                <button
                  key={item.value}
                  type="button"
                  onClick={() => setFormat(item.value)}
                  className={`rounded-lg border p-4 text-left transition-colors ${
                    format === item.value ? "border-emerald-500/60 bg-emerald-500/10" : "border-slate-800 bg-slate-950/40 hover:border-slate-700"
                  }`}
                >
                  <div className="text-sm font-semibold text-white">{item.label}</div>
                  <p className="mt-1 text-xs leading-5 text-slate-500">{item.desc}</p>
                </button>
              ))}
            </div>
          </div>

          <div className="grid content-start gap-4">
            <label>
              <span className="mb-2 block text-sm font-medium text-slate-300">Report type</span>
              <Select value={type} onChange={(e) => setType(e.target.value)}>
                {TYPES.map((item) => (
                  <option key={item} value={item}>
                    {TYPE_LABELS[item] ?? item}
                  </option>
                ))}
              </Select>
            </label>
            {format === "pdf" && (
              <div className="flex gap-2 rounded-lg border border-sky-500/30 bg-sky-500/10 p-3 text-xs leading-5 text-sky-200">
                <Info className="mt-0.5 h-4 w-4 flex-shrink-0" />
                PDF is experimental. If PDF rendering fails, the generated report downloads as HTML.
              </div>
            )}
            {diffCandidates.length > 0 && (
              <label>
                <span className="mb-2 block text-sm font-medium text-slate-300">Compare scan</span>
                <Select value={compareScanId} onChange={(e) => setCompareScanId(e.target.value)}>
                  <option value="">No cross-scan diff</option>
                  {diffCandidates.map((candidate: any) => (
                    <option key={candidate.id} value={candidate.id}>
                      {candidate.auth_method} · {candidate.id.slice(0, 8)}
                    </option>
                  ))}
                </Select>
              </label>
            )}
            <Button onClick={() => generateMutation.mutate()} disabled={generateMutation.isPending}>
              {generateMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
              Generate
            </Button>
          </div>
        </div>

        <div className="mt-5 border-t border-slate-800 pt-5">
          <button
            type="button"
            onClick={() => setMetadataOpen((value) => !value)}
            className="flex w-full items-center justify-between rounded-lg border border-slate-800 bg-slate-950/40 px-4 py-3 text-left text-sm font-semibold text-white hover:border-slate-700"
          >
            <span>Advanced report metadata</span>
            {metadataOpen ? <ChevronDown className="h-4 w-4 text-slate-500" /> : <ChevronRight className="h-4 w-4 text-slate-500" />}
          </button>
          {metadataOpen && (
            <div className="mt-4 grid gap-4">
              <div className="grid gap-4 md:grid-cols-2">
                <Field label="Report title">
                  <TextInput value={metadata.report_title} maxLength={255} onChange={(e) => setMetadata({ ...metadata, report_title: e.target.value })} placeholder="웹 애플리케이션 보안 진단 보고서" />
                </Field>
                <Field label="Client name">
                  <TextInput value={metadata.client_name} maxLength={255} onChange={(e) => setMetadata({ ...metadata, client_name: e.target.value })} placeholder="Example Corp" />
                </Field>
                <Field label="Service name">
                  <TextInput value={metadata.service_name} maxLength={255} onChange={(e) => setMetadata({ ...metadata, service_name: e.target.value })} placeholder="Partner Portal" />
                </Field>
                <Field label="Organization name">
                  <TextInput value={metadata.organization_name} maxLength={255} onChange={(e) => setMetadata({ ...metadata, organization_name: e.target.value })} />
                </Field>
                <Field label="Author">
                  <TextInput value={metadata.author} maxLength={255} onChange={(e) => setMetadata({ ...metadata, author: e.target.value })} />
                </Field>
                <Field label="Reviewer">
                  <TextInput value={metadata.reviewer} maxLength={255} onChange={(e) => setMetadata({ ...metadata, reviewer: e.target.value })} />
                </Field>
                <Field label="Document version">
                  <TextInput value={metadata.document_version} maxLength={50} onChange={(e) => setMetadata({ ...metadata, document_version: e.target.value })} placeholder="1.0" />
                </Field>
                <Field label="Report ID">
                  <TextInput value={metadata.report_id} maxLength={100} onChange={(e) => setMetadata({ ...metadata, report_id: e.target.value })} />
                </Field>
                <Field label="Classification">
                  <Select value={metadata.classification} onChange={(e) => setMetadata({ ...metadata, classification: e.target.value })}>
                    {CLASSIFICATIONS.map((item) => <option key={item || "none"} value={item}>{item || "Default"}</option>)}
                  </Select>
                </Field>
                <Field label="Contact">
                  <TextInput value={metadata.contact} maxLength={255} onChange={(e) => setMetadata({ ...metadata, contact: e.target.value })} />
                </Field>
                <Field label="Assessment start date">
                  <TextInput type="date" value={metadata.assessment_start_date} onChange={(e) => setMetadata({ ...metadata, assessment_start_date: e.target.value })} />
                </Field>
                <Field label="Assessment end date">
                  <TextInput type="date" value={metadata.assessment_end_date} onChange={(e) => setMetadata({ ...metadata, assessment_end_date: e.target.value })} />
                </Field>
                <Field label="Prepared date">
                  <TextInput type="date" value={metadata.prepared_date} onChange={(e) => setMetadata({ ...metadata, prepared_date: e.target.value })} />
                </Field>
                <Field label="Remediation due date">
                  <TextInput type="date" value={metadata.remediation_due_date} onChange={(e) => setMetadata({ ...metadata, remediation_due_date: e.target.value })} />
                </Field>
              </div>
              <Field label="Assessment scope">
                <TextArea value={metadata.assessment_scope} maxLength={4000} rows={3} onChange={(e) => setMetadata({ ...metadata, assessment_scope: e.target.value })} className="resize-y" />
              </Field>
              <div className="grid gap-4 md:grid-cols-3">
                <Field label="Out of scope" hint="One item per line.">
                  <TextArea value={metadata.out_of_scope} rows={4} onChange={(e) => setMetadata({ ...metadata, out_of_scope: e.target.value })} className="resize-y" />
                </Field>
                <Field label="Methodology" hint="One item per line.">
                  <TextArea value={metadata.methodology} rows={4} onChange={(e) => setMetadata({ ...metadata, methodology: e.target.value })} className="resize-y" />
                </Field>
                <Field label="Limitations" hint="One item per line.">
                  <TextArea value={metadata.limitations} rows={4} onChange={(e) => setMetadata({ ...metadata, limitations: e.target.value })} className="resize-y" />
                </Field>
              </div>
              <Field label="Executive summary note">
                <TextArea value={metadata.executive_summary_note} maxLength={4000} rows={3} onChange={(e) => setMetadata({ ...metadata, executive_summary_note: e.target.value })} className="resize-y" />
              </Field>
              <Field label="Custom notes">
                <TextArea value={metadata.custom_notes} maxLength={4000} rows={3} onChange={(e) => setMetadata({ ...metadata, custom_notes: e.target.value })} className="resize-y" />
              </Field>
            </div>
          )}
        </div>
      </Card>

      <Card>
        <div className="border-b border-slate-800 px-5 py-4">
          <h2 className="font-semibold text-white">Generated reports</h2>
          <p className="mt-0.5 text-xs text-slate-500">{reports.length} report{reports.length === 1 ? "" : "s"}</p>
        </div>

        {isLoading ? (
          <div className="p-8 text-sm text-slate-500">Loading reports...</div>
        ) : reports.length === 0 ? (
          <div className="p-5">
            <EmptyState icon={<FileText className="h-10 w-10" />} title="No reports yet" description="Generate a report after the scan completes." />
          </div>
        ) : (
          <div className="divide-y divide-slate-800">
            {reports.map((report: any) => {
              const isJson = report.format === "json";
              return (
                <div key={report.id} className="grid gap-3 px-5 py-4 md:grid-cols-[auto_1fr_auto] md:items-center">
                  <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-3">
                    {isJson ? <FileJson className="h-5 w-5 text-sky-300" /> : <FileText className="h-5 w-5 text-emerald-300" />}
                  </div>
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-sm font-semibold text-white">{TYPE_LABELS[report.report_type] ?? report.report_type}</span>
                      <Badge tone="neutral">{report.format}</Badge>
                    </div>
                    <p className="mt-1 text-xs text-slate-500">
                      {formatDistanceToNow(new Date(report.created_at), { addSuffix: true })}
                      {report.file_size ? ` · ${(report.file_size / 1024).toFixed(0)} KB` : " · queued"}
                    </p>
                    {report.format === "pdf" && report.file_path?.endsWith(".html") && (
                      <p className="mt-1 text-xs text-sky-300">PDF renderer fell back to HTML output.</p>
                    )}
                  </div>
                  {report.file_path ? (
                    <Button variant="secondary" onClick={() => downloadMutation.mutate(report.id)} disabled={downloadMutation.isPending && downloadingId === report.id}>
                      {downloadMutation.isPending && downloadingId === report.id ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />}
                      Download
                    </Button>
                  ) : (
                    <span className="inline-flex items-center gap-2 text-sm text-slate-500">
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Generating
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </Card>
    </PageShell>
  );
}
