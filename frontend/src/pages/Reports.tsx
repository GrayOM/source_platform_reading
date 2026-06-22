import { useState } from "react";
import { useParams } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { FileText, Download, Loader2, Plus } from "lucide-react";
import toast from "react-hot-toast";
import { getScanReports, generateReport, downloadReport } from "../lib/api";
import { formatDistanceToNow } from "date-fns";

const FORMATS = ["pdf", "html", "json", "markdown"] as const;
const TYPES = ["full", "kisa", "owasp", "executive", "technical"] as const;
const TYPE_LABELS: Record<string, string> = {
  full: "Full Report",
  kisa: "KISA Format (한국)",
  owasp: "OWASP Top 10",
  executive: "Executive Summary",
  technical: "Technical Details",
};

export function Reports() {
  const { scanId } = useParams<{ scanId: string }>();
  const qc = useQueryClient();
  const [format, setFormat] = useState<string>("pdf");
  const [type, setType] = useState<string>("full");

  const { data: reports = [], isLoading } = useQuery({
    queryKey: ["reports", scanId],
    queryFn: () => getScanReports(scanId!),
    refetchInterval: (data: any) =>
      (data ?? []).some((r: any) => !r.file_path) ? 3000 : false,
  });

  const generateMutation = useMutation({
    mutationFn: () => generateReport(scanId!, format, type),
    onSuccess: () => {
      toast.success("Report generation started");
      qc.invalidateQueries({ queryKey: ["reports", scanId] });
    },
    onError: (err: any) => toast.error(err.response?.data?.detail ?? "Failed"),
  });

  const downloadMutation = useMutation({
    mutationFn: (reportId: string) => downloadReport(reportId),
    onError: (err: any) => toast.error(err.response?.data?.detail ?? "Download failed"),
  });

  return (
    <div className="p-8 max-w-3xl mx-auto">
      <h1 className="text-2xl font-bold text-white mb-6">Reports</h1>

      {/* Generate new */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 mb-6">
        <h2 className="text-sm font-semibold text-gray-300 mb-4">Generate New Report</h2>
        <div className="grid grid-cols-2 gap-4 mb-4">
          <div>
            <label className="text-xs text-gray-500 block mb-2">Format</label>
            <div className="flex gap-2 flex-wrap">
              {FORMATS.map((f) => (
                <button
                  key={f}
                  onClick={() => setFormat(f)}
                  className={`px-3 py-1.5 rounded-lg text-xs font-medium uppercase transition-colors ${
                    format === f ? "bg-emerald-500 text-black" : "bg-gray-800 text-gray-400 hover:text-white"
                  }`}
                >
                  {f}
                </button>
              ))}
            </div>
          </div>
          <div>
            <label className="text-xs text-gray-500 block mb-2">Type</label>
            <select
              value={type}
              onChange={(e) => setType(e.target.value)}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-emerald-500"
            >
              {TYPES.map((t) => (
                <option key={t} value={t}>{TYPE_LABELS[t] ?? t}</option>
              ))}
            </select>
          </div>
        </div>
        <button
          onClick={() => generateMutation.mutate()}
          disabled={generateMutation.isPending}
          className="flex items-center gap-2 bg-emerald-500 hover:bg-emerald-400 disabled:bg-gray-700 text-black font-semibold px-4 py-2.5 rounded-lg text-sm transition-colors"
        >
          {generateMutation.isPending ? (
            <Loader2 className="w-4 h-4 animate-spin" />
          ) : (
            <Plus className="w-4 h-4" />
          )}
          Generate
        </button>
      </div>

      {/* Reports list */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl divide-y divide-gray-800">
        {isLoading ? (
          <div className="p-8 text-center text-gray-500">Loading...</div>
        ) : reports.length === 0 ? (
          <div className="p-8 text-center text-gray-500">
            <FileText className="w-8 h-8 mx-auto mb-2 opacity-30" />
            <p>No reports yet</p>
          </div>
        ) : (
          reports.map((r: any) => (
            <div key={r.id} className="flex items-center gap-4 p-4">
              <FileText className="w-5 h-5 text-gray-500 shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="text-sm font-medium text-white">
                  {TYPE_LABELS[r.report_type] ?? r.report_type} — {r.format.toUpperCase()}
                </div>
                <div className="text-xs text-gray-500 mt-0.5">
                  {formatDistanceToNow(new Date(r.created_at), { addSuffix: true })}
                  {r.file_size ? ` · ${(r.file_size / 1024).toFixed(0)} KB` : ""}
                </div>
              </div>
              {r.file_path ? (
                <button
                  onClick={() => downloadMutation.mutate(r.id)}
                  className="flex items-center gap-1.5 text-xs text-emerald-400 hover:text-emerald-300 font-medium"
                >
                  <Download className="w-3.5 h-3.5" /> Download
                </button>
              ) : (
                <span className="flex items-center gap-1.5 text-xs text-gray-500">
                  <Loader2 className="w-3.5 h-3.5 animate-spin" /> Generating...
                </span>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}
