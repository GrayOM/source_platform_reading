import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Plus, Globe, AlertTriangle, CheckCircle, Clock, XCircle } from "lucide-react";
import { getScans, getProjects } from "../lib/api";
import { formatDistanceToNow } from "date-fns";

const STATUS_ICON: Record<string, React.ReactNode> = {
  completed: <CheckCircle className="w-4 h-4 text-emerald-400" />,
  crawling: <Clock className="w-4 h-4 text-blue-400 animate-spin" />,
  analyzing: <Clock className="w-4 h-4 text-purple-400 animate-spin" />,
  failed: <XCircle className="w-4 h-4 text-red-400" />,
  pending: <Clock className="w-4 h-4 text-gray-400" />,
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-green-400",
};

export function Dashboard() {
  const { data: scans = [] } = useQuery({ queryKey: ["scans"], queryFn: () => getScans() });
  const { data: projects = [] } = useQuery({ queryKey: ["projects"], queryFn: getProjects });

  const recentScans = scans.slice(0, 8);
  const totalFindings = scans.reduce((s: number, sc: any) => s + (sc.findings_count ?? 0), 0);
  const activeScans = scans.filter((s: any) => ["crawling", "analyzing"].includes(s.status)).length;

  return (
    <div className="p-8 max-w-6xl mx-auto">
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold text-white">Dashboard</h1>
          <p className="text-sm text-gray-500 mt-1">Security assessment overview</p>
        </div>
        <Link
          to="/scans/new"
          className="flex items-center gap-2 bg-emerald-500 hover:bg-emerald-400 text-black font-semibold px-4 py-2 rounded-lg text-sm transition-colors"
        >
          <Plus className="w-4 h-4" /> New Scan
        </Link>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4 mb-8">
        {[
          { label: "Projects", value: projects.length, color: "text-blue-400" },
          { label: "Total Scans", value: scans.length, color: "text-white" },
          { label: "Active Scans", value: activeScans, color: "text-yellow-400" },
          { label: "Total Findings", value: totalFindings, color: "text-red-400" },
        ].map(({ label, value, color }) => (
          <div key={label} className="bg-gray-900 border border-gray-800 rounded-xl p-5">
            <div className={`text-3xl font-bold ${color}`}>{value}</div>
            <div className="text-sm text-gray-500 mt-1">{label}</div>
          </div>
        ))}
      </div>

      {/* Recent Scans */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl">
        <div className="px-6 py-4 border-b border-gray-800 flex items-center justify-between">
          <h2 className="font-semibold text-white">Recent Scans</h2>
          <Link to="/projects" className="text-xs text-emerald-400 hover:underline">View all →</Link>
        </div>
        {recentScans.length === 0 ? (
          <div className="text-center py-16 text-gray-500">
            <Globe className="w-10 h-10 mx-auto mb-3 opacity-30" />
            <p>No scans yet.</p>
            <Link to="/scans/new" className="text-emerald-400 hover:underline text-sm mt-2 inline-block">
              Start your first scan →
            </Link>
          </div>
        ) : (
          <div className="divide-y divide-gray-800">
            {recentScans.map((scan: any) => (
              <Link
                key={scan.id}
                to={`/scans/${scan.id}`}
                className="flex items-center gap-4 px-6 py-4 hover:bg-gray-800/50 transition-colors"
              >
                <div className="flex-shrink-0">{STATUS_ICON[scan.status] ?? STATUS_ICON.pending}</div>
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-white truncate">{scan.target_url}</div>
                  <div className="text-xs text-gray-500 mt-0.5">
                    {formatDistanceToNow(new Date(scan.created_at), { addSuffix: true })}
                    {" · "}
                    <span className="capitalize">{scan.status}</span>
                  </div>
                </div>
                {scan.findings_count > 0 && (
                  <div className="flex-shrink-0 flex items-center gap-1 text-xs text-red-400 font-semibold">
                    <AlertTriangle className="w-3.5 h-3.5" />
                    {scan.findings_count} findings
                  </div>
                )}
                {scan.status === "completed" && scan.findings_count === 0 && (
                  <span className="text-xs text-emerald-400 font-semibold">Clean</span>
                )}
                <div className="w-16 flex-shrink-0">
                  <div className="h-1.5 bg-gray-700 rounded-full">
                    <div
                      className="h-1.5 bg-emerald-500 rounded-full transition-all"
                      style={{ width: `${scan.progress ?? 0}%` }}
                    />
                  </div>
                </div>
              </Link>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
