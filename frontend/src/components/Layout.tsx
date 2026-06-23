import { Link, Outlet, useLocation, useNavigate } from "react-router-dom";
import { FileSearch, FolderOpen, LayoutDashboard, LogOut, Plus, Shield } from "lucide-react";
import clsx from "clsx";

const nav = [
  { to: "/", icon: LayoutDashboard, label: "Dashboard" },
  { to: "/projects", icon: FolderOpen, label: "Projects" },
  { to: "/scans/new", icon: Plus, label: "New Scan" },
];

export function Layout() {
  const { pathname } = useLocation();
  const navigate = useNavigate();

  const logout = () => {
    localStorage.clear();
    navigate("/login");
  };

  const isActive = (to: string) => (to === "/" ? pathname === "/" : pathname.startsWith(to));

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <aside className="fixed inset-y-0 left-0 z-20 hidden w-64 flex-col border-r border-slate-800 bg-slate-950/95 lg:flex">
        <div className="border-b border-slate-800 px-5 py-5">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-emerald-500/30 bg-emerald-500/10">
              <Shield className="h-5 w-5 text-emerald-300" />
            </div>
            <div>
              <div className="text-base font-semibold text-white">SSS Platform</div>
              <div className="text-xs text-slate-500">Security assessment MVP</div>
            </div>
          </div>
        </div>
        <nav className="flex-1 space-y-1 px-3 py-4">
          {nav.map(({ to, icon: Icon, label }) => (
            <Link
              key={to}
              to={to}
              className={clsx(
                "flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors",
                isActive(to)
                  ? "border border-emerald-500/30 bg-emerald-500/10 text-emerald-200"
                  : "text-slate-400 hover:bg-slate-900 hover:text-white"
              )}
            >
              <Icon className="h-4 w-4" />
              {label}
            </Link>
          ))}
        </nav>
        <div className="mx-3 mb-3 rounded-lg border border-slate-800 bg-slate-900/70 p-3">
          <div className="flex items-center gap-2 text-xs font-semibold text-slate-300">
            <FileSearch className="h-3.5 w-3.5 text-sky-300" />
            Report-ready findings
          </div>
          <p className="mt-1 text-xs leading-5 text-slate-500">Collect browser-visible resources and API flows, then export HTML, Markdown, or JSON.</p>
        </div>
        <button
          onClick={logout}
          className="flex items-center gap-3 border-t border-slate-800 px-5 py-4 text-sm text-slate-500 transition-colors hover:text-slate-200"
        >
          <LogOut className="h-4 w-4" />
          Sign out
        </button>
      </aside>

      <header className="sticky top-0 z-10 border-b border-slate-800 bg-slate-950/90 px-4 py-3 backdrop-blur lg:hidden">
        <div className="flex items-center justify-between">
          <Link to="/" className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-emerald-300" />
            <span className="text-sm font-semibold">SSS Platform</span>
          </Link>
          <button onClick={logout} className="rounded-lg p-2 text-slate-400 hover:bg-slate-900 hover:text-white" aria-label="Sign out">
            <LogOut className="h-4 w-4" />
          </button>
        </div>
        <nav className="mt-3 flex gap-2 overflow-x-auto pb-1">
          {nav.map(({ to, label }) => (
            <Link
              key={to}
              to={to}
              className={clsx(
                "whitespace-nowrap rounded-lg px-3 py-2 text-xs font-semibold",
                isActive(to) ? "bg-emerald-500 text-slate-950" : "bg-slate-900 text-slate-400"
              )}
            >
              {label}
            </Link>
          ))}
        </nav>
      </header>

      <main className="min-h-screen lg:pl-64">
        <Outlet />
      </main>
    </div>
  );
}
