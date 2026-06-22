import { useParams, Link } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import { AlertTriangle, FileText, Globe, Layers, CheckCircle, XCircle, Loader2 } from "lucide-react";
import { getScan } from "../lib/api";
import { useScanProgress } from "../hooks/useScanProgress";
import { formatDistanceToNow } from "date-fns";

const STATUS_CONFIG: Record<string, { color: string; icon: React.ReactNode; label: string }> = {
  pending:        { color: "text-gray-400",   icon: <Loader2 className="w-4 h-4" />, label: "Pending" },
  authenticating: { color: "text-yellow-400", icon: <Loader2 className="w-4 h-4 animate-spin" />, label: "Authenticating" },
  crawling:       { color: "text-blue-400",   icon: <Globe className="w-4 h-4 animate-pulse" />, label: "Crawling" },
  analyzing:      { color: "text-purple-400", icon: <Loader2 className="w-4 h-4 animate-spin" />, label: "Analyzing" },
  reporting:      { color: "text-indigo-400", icon: <FileText className="w-4 h-4 animate-pulse" />, label: "Generating report" },
  completed:      { color: "text-emerald-400", icon: <CheckCircle className="w-4 h-4" />, label: "Completed" },
  failed:         { color: "text-red-400",    icon: <XCircle className="w-4 h-4" />, label: "Failed" },
  cancelled:      { color: "text-gray-500",   icon: <XCircle className="w-4 h-4" />, label: "Cancelled" },
};

export function ScanDetail() {
  const { scanId } = useParams<{ scanId: string }>();
  const qc = useQueryClient();

  const { data: scan, isLoading } = useQuery({
    queryKey: ["scan", scanId],
    queryFn: () => getScan(scanId!),
    refetchInterval: (query) => {
      const data = query.state.data as any;
      const active = ["pending", "crawling", "analyzing", "authenticating", "reporting"];
      return data && active.includes(data.status) ? 3000 : false;
    },
  });

  const wsProgress = useScanProgress(
    scanId,
    scan && ["crawling", "analyzing", "authenticating", "reporting"].includes(scan.status)
  );

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

  if (isLoading) return <div className="p-8 text-gray-500">Loading...</div>;
  if (!scan) return <div className="p-8 text-gray-500">Scan not found</div>;

  const status = STATUS_CONFIG[scan.status] ?? STATUS_CONFIG.pending;
  const isActive = ["crawling", "analyzing", "authenticating", "reporting"].includes(scan.status);

  return (
    <div className="p-8 max-w-4xl mx-auto">
      <div className="mb-6">
        <div className="flex items-center gap-3 mb-1">
          <span className={`flex items-center gap-1.5 ${status.color}`}>
            {status.icon}
            <span className="text-sm font-medium">{status.label}</span>
          </span>
          <span className="text-gray-600">·</span>
          <span className="text-xs text-gray-500">
            Started {formatDistanceToNow(new Date(scan.started_at ?? scan.created_at), { addSuffix: true })}
          </span>
        </div>
        <h1 className="text-xl font-bold text-white break-all">{scan.target_url}</h1>
        <p className="text-xs text-gray-500 mt-1 font-mono">{scan.id}</p>
      </div>

      {/* Progress */}
      {isActive && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 mb-6">
          <div className="flex justify-between text-sm mb-3">
            <span className="text-gray-400">{wsProgress?.message ?? `${status.label}...`}</span>
            <span className="text-white font-medium">{scan.progress}%</span>
          </div>
          <div className="h-2 bg-gray-800 rounded-full overflow-hidden">
            <div
              className="h-2 bg-emerald-500 rounded-full transition-all duration-500"
              style={{ width: `${scan.progress}%` }}
            />
          </div>
        </div>
      )}

      {scan.error_message && (
        <div className="bg-red-900/20 border border-red-800 rounded-xl p-4 mb-6 text-sm text-red-300">
          <strong>Error:</strong> {scan.error_message}
        </div>
      )}

      {/* Stats */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        {[
          { icon: Globe, label: "Pages", value: scan.pages_discovered, color: "text-blue-400" },
          { icon: Layers, label: "Resources", value: scan.resources_collected, color: "text-purple-400" },
          { icon: AlertTriangle, label: "Findings", value: scan.findings_count, color: scan.findings_count > 0 ? "text-red-400" : "text-emerald-400" },
        ].map(({ icon: Icon, label, value, color }) => (
          <div key={label} className="bg-gray-900 border border-gray-800 rounded-xl p-5 text-center">
            <Icon className={`w-5 h-5 mx-auto mb-2 ${color}`} />
            <div className={`text-2xl font-bold ${color}`}>{value ?? 0}</div>
            <div className="text-xs text-gray-500 mt-1">{label}</div>
          </div>
        ))}
      </div>

      {/* Action buttons */}
      {scan.status === "completed" && (
        <div className="flex gap-3">
          <Link
            to={`/scans/${scanId}/findings`}
            className="flex items-center gap-2 bg-gray-800 hover:bg-gray-700 border border-gray-700 text-white px-4 py-2.5 rounded-lg text-sm font-medium transition-colors"
          >
            <AlertTriangle className="w-4 h-4 text-orange-400" />
            View Findings
          </Link>
          <Link
            to={`/scans/${scanId}/reports`}
            className="flex items-center gap-2 bg-emerald-500 hover:bg-emerald-400 text-black px-4 py-2.5 rounded-lg text-sm font-semibold transition-colors"
          >
            <FileText className="w-4 h-4" />
            Generate Report
          </Link>
        </div>
      )}
    </div>
  );
}
