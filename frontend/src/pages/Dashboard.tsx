import { useQuery } from "@tanstack/react-query";
import { formatDistanceToNow } from "date-fns";
import { AlertTriangle, CheckCircle, Clock, FileSearch, FolderOpen, Globe, Plus, ShieldCheck, XCircle } from "lucide-react";
import { Link } from "react-router-dom";
import { Badge, Card, EmptyState, PageHeader, PageShell } from "../components/ui";
import { getProjects, getScans } from "../lib/api";

const STATUS_ICON: Record<string, React.ReactNode> = {
  completed: <CheckCircle className="h-4 w-4 text-emerald-300" />,
  crawling: <Clock className="h-4 w-4 animate-spin text-sky-300" />,
  analyzing: <Clock className="h-4 w-4 animate-spin text-blue-300" />,
  failed: <XCircle className="h-4 w-4 text-red-300" />,
  pending: <Clock className="h-4 w-4 text-slate-400" />,
};

export function Dashboard() {
  const { data: scans = [], isLoading: scansLoading } = useQuery({ queryKey: ["scans"], queryFn: () => getScans() });
  const { data: projects = [], isLoading: projectsLoading } = useQuery({ queryKey: ["projects"], queryFn: getProjects });

  const isLoading = scansLoading || projectsLoading;
  const recentScans = scans.slice(0, 8);
  const totalFindings = scans.reduce((sum: number, scan: any) => sum + (scan.findings_count ?? 0), 0);
  const activeScans = scans.filter((scan: any) => ["pending", "authenticating", "crawling", "analyzing", "reporting"].includes(scan.status)).length;
  const completedScans = scans.filter((scan: any) => scan.status === "completed").length;

  return (
    <PageShell>
      <PageHeader
        title="Dashboard"
        description="Monitor scans, findings, and report-ready assessment activity across your projects."
        action={
          <Link
            to="/scans/new"
            className="inline-flex items-center justify-center gap-2 rounded-lg bg-emerald-500 px-4 py-2.5 text-sm font-semibold text-slate-950 transition-colors hover:bg-emerald-400"
          >
            <Plus className="h-4 w-4" />
            New Scan
          </Link>
        }
      />

      <div className="mb-6 grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        {[
          { label: "Projects", value: projects.length, icon: FolderOpen, color: "text-sky-300" },
          { label: "Total scans", value: scans.length, icon: FileSearch, color: "text-white" },
          { label: "Completed", value: completedScans, icon: ShieldCheck, color: "text-emerald-300" },
          { label: "Findings", value: totalFindings, icon: AlertTriangle, color: "text-orange-300" },
        ].map(({ label, value, icon: Icon, color }) => (
          <Card key={label} className="p-5">
            <div className="flex items-center justify-between gap-4">
              <div>
                <div className={`text-3xl font-semibold ${color}`}>{isLoading ? "..." : value}</div>
                <div className="mt-1 text-sm text-slate-500">{label}</div>
              </div>
              <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-3">
                <Icon className={`h-5 w-5 ${color}`} />
              </div>
            </div>
          </Card>
        ))}
      </div>

      <Card>
        <div className="flex items-center justify-between border-b border-slate-800 px-5 py-4">
          <div>
            <h2 className="font-semibold text-white">Recent scans</h2>
            <p className="mt-0.5 text-xs text-slate-500">{activeScans} active scan{activeScans === 1 ? "" : "s"}</p>
          </div>
          <Link to="/projects" className="text-xs font-semibold text-emerald-300 hover:text-emerald-200">
            Projects
          </Link>
        </div>

        {isLoading ? (
          <div className="p-8 text-sm text-slate-500">Loading assessment activity...</div>
        ) : recentScans.length === 0 ? (
          <div className="p-5">
            <EmptyState
              icon={<Globe className="h-10 w-10" />}
              title="No scans yet"
              description="Create a project and start a scan to collect pages, resources, findings, and reports."
              action={
                <Link to="/scans/new" className="inline-flex rounded-lg bg-emerald-500 px-4 py-2 text-sm font-semibold text-slate-950 hover:bg-emerald-400">
                  Start first scan
                </Link>
              }
            />
          </div>
        ) : (
          <div className="divide-y divide-slate-800">
            {recentScans.map((scan: any) => (
              <Link key={scan.id} to={`/scans/${scan.id}`} className="grid gap-3 px-5 py-4 transition-colors hover:bg-slate-800/40 md:grid-cols-[1fr_auto_auto] md:items-center">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="flex-shrink-0">{STATUS_ICON[scan.status] ?? STATUS_ICON.pending}</span>
                    <span className="truncate text-sm font-medium text-white">{scan.target_url}</span>
                  </div>
                  <div className="mt-1 text-xs text-slate-500">
                    {formatDistanceToNow(new Date(scan.created_at), { addSuffix: true })}
                    {" · "}
                    <span className="capitalize">{scan.status}</span>
                  </div>
                </div>
                <Badge tone={scan.findings_count > 0 ? "high" : scan.status === "completed" ? "low" : "neutral"}>
                  {scan.findings_count > 0 ? `${scan.findings_count} findings` : scan.status === "completed" ? "No findings" : "In progress"}
                </Badge>
                <div className="h-2 w-full overflow-hidden rounded-full bg-slate-800 md:w-28">
                  <div className="h-full rounded-full bg-emerald-400 transition-all" style={{ width: `${scan.progress ?? 0}%` }} />
                </div>
              </Link>
            ))}
          </div>
        )}
      </Card>
    </PageShell>
  );
}
