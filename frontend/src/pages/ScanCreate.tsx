import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery } from "@tanstack/react-query";
import { Globe, Key, Cookie, Chrome, ChevronRight, ChevronLeft, Loader2 } from "lucide-react";
import toast from "react-hot-toast";
import { createScan, getProjects, startBrowserAuth } from "../lib/api";

type AuthMethod = "none" | "browser" | "cookies" | "bearer";

const STEPS = ["Target", "Authentication", "Settings", "Review"];

export function ScanCreate() {
  const navigate = useNavigate();
  const [step, setStep] = useState(0);
  const [loading, setLoading] = useState(false);

  const [form, setForm] = useState({
    project_id: "",
    target_url: "",
    auth_method: "none" as AuthMethod,
    bearer_token: "",
    cookies_json: "",
    max_depth: 5,
    max_pages: 500,
    excluded_paths: "",
    follow_subdomains: false,
    screenshot_pages: true,
    analyze_source_maps: true,
  });

  const { data: projects = [] } = useQuery({ queryKey: ["projects"], queryFn: getProjects });

  const set = (k: string, v: unknown) => setForm((f) => ({ ...f, [k]: v }));

  const submit = async () => {
    setLoading(true);
    try {
      const excluded = form.excluded_paths
        .split("\n")
        .map((p) => p.trim())
        .filter(Boolean);

      const payload = {
        project_id: form.project_id,
        target_url: form.target_url,
        config: {
          max_depth: form.max_depth,
          max_pages: form.max_pages,
          excluded_paths: excluded,
          follow_subdomains: form.follow_subdomains,
          screenshot_pages: form.screenshot_pages,
          analyze_source_maps: form.analyze_source_maps,
        },
        auth: {
          method: form.auth_method,
          bearer_token: form.auth_method === "bearer" ? form.bearer_token : undefined,
          cookies_json: form.auth_method === "cookies" ? form.cookies_json : undefined,
        },
      };

      const scan = await createScan(payload);

      if (form.auth_method === "browser") {
        await startBrowserAuth(scan.id);
        toast.success("Browser window opened — log in, then click 'Done'");
      } else {
        toast.success("Scan started!");
      }

      navigate(`/scans/${scan.id}`);
    } catch (err: any) {
      toast.error(err.response?.data?.detail ?? "Failed to create scan");
    } finally {
      setLoading(false);
    }
  };

  const canNext = () => {
    if (step === 0) return form.target_url.startsWith("http") && form.project_id;
    if (step === 1) {
      if (form.auth_method === "bearer") return !!form.bearer_token;
      if (form.auth_method === "cookies") return !!form.cookies_json;
      return true;
    }
    return true;
  };

  return (
    <div className="p-8 max-w-2xl mx-auto">
      <h1 className="text-2xl font-bold text-white mb-2">New Scan</h1>
      <p className="text-sm text-gray-500 mb-8">Configure a security assessment</p>

      {/* Progress bar */}
      <div className="flex items-center gap-2 mb-8">
        {STEPS.map((label, i) => (
          <div key={label} className="flex items-center gap-2">
            <div
              className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold border-2 transition-colors ${
                i < step
                  ? "bg-emerald-500 border-emerald-500 text-black"
                  : i === step
                  ? "border-emerald-500 text-emerald-400"
                  : "border-gray-700 text-gray-600"
              }`}
            >
              {i < step ? "✓" : i + 1}
            </div>
            <span className={`text-sm ${i === step ? "text-white font-medium" : "text-gray-500"}`}>{label}</span>
            {i < STEPS.length - 1 && <ChevronRight className="w-3 h-3 text-gray-700" />}
          </div>
        ))}
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl p-6">
        {/* Step 0: Target */}
        {step === 0 && (
          <div className="space-y-4">
            <h2 className="text-lg font-semibold text-white mb-4">Target</h2>
            <div>
              <label className="text-sm text-gray-400 block mb-2">Project</label>
              <select
                value={form.project_id}
                onChange={(e) => set("project_id", e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-sm text-white focus:outline-none focus:border-emerald-500"
              >
                <option value="">Select a project</option>
                {projects.map((p: any) => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-sm text-gray-400 block mb-2">Target URL</label>
              <div className="relative">
                <Globe className="absolute left-3 top-2.5 w-4 h-4 text-gray-500" />
                <input
                  type="url"
                  placeholder="https://example.com"
                  value={form.target_url}
                  onChange={(e) => set("target_url", e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg pl-9 pr-4 py-2.5 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-emerald-500"
                />
              </div>
            </div>
          </div>
        )}

        {/* Step 1: Auth */}
        {step === 1 && (
          <div className="space-y-4">
            <h2 className="text-lg font-semibold text-white mb-4">Authentication</h2>
            <div className="grid grid-cols-2 gap-3">
              {[
                { value: "none", icon: Globe, label: "No Auth", desc: "Public site" },
                { value: "browser", icon: Chrome, label: "Browser Login", desc: "Login manually" },
                { value: "cookies", icon: Cookie, label: "Paste Cookies", desc: "JSON / Netscape format" },
                { value: "bearer", icon: Key, label: "Bearer Token", desc: "API token or JWT" },
              ].map(({ value, icon: Icon, label, desc }) => (
                <button
                  key={value}
                  onClick={() => set("auth_method", value)}
                  className={`flex items-start gap-3 p-4 rounded-xl border-2 text-left transition-colors ${
                    form.auth_method === value
                      ? "border-emerald-500 bg-emerald-500/5"
                      : "border-gray-700 hover:border-gray-600"
                  }`}
                >
                  <Icon className="w-5 h-5 text-emerald-400 mt-0.5 flex-shrink-0" />
                  <div>
                    <div className="text-sm font-medium text-white">{label}</div>
                    <div className="text-xs text-gray-500">{desc}</div>
                  </div>
                </button>
              ))}
            </div>

            {form.auth_method === "browser" && (
              <div className="bg-blue-500/10 border border-blue-500/20 rounded-xl p-4 text-sm text-blue-300">
                A browser window will open when the scan starts. Log in to the target site, then click the green "Done" button.
              </div>
            )}
            {form.auth_method === "bearer" && (
              <div>
                <label className="text-sm text-gray-400 block mb-2">Bearer Token</label>
                <input
                  type="password"
                  placeholder="eyJ... or your API key"
                  value={form.bearer_token}
                  onChange={(e) => set("bearer_token", e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-sm text-white font-mono placeholder-gray-500 focus:outline-none focus:border-emerald-500"
                />
              </div>
            )}
            {form.auth_method === "cookies" && (
              <div>
                <label className="text-sm text-gray-400 block mb-2">
                  Cookies (JSON array from DevTools or Burp)
                </label>
                <textarea
                  rows={6}
                  placeholder='[{"name": "session", "value": "...", "domain": "example.com"}]'
                  value={form.cookies_json}
                  onChange={(e) => set("cookies_json", e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-sm text-white font-mono placeholder-gray-500 focus:outline-none focus:border-emerald-500 resize-none"
                />
              </div>
            )}
          </div>
        )}

        {/* Step 2: Settings */}
        {step === 2 && (
          <div className="space-y-4">
            <h2 className="text-lg font-semibold text-white mb-4">Crawl Settings</h2>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="text-sm text-gray-400 block mb-2">Max Depth</label>
                <input
                  type="number"
                  min={1}
                  max={20}
                  value={form.max_depth}
                  onChange={(e) => set("max_depth", +e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-sm text-white focus:outline-none focus:border-emerald-500"
                />
              </div>
              <div>
                <label className="text-sm text-gray-400 block mb-2">Max Pages</label>
                <input
                  type="number"
                  min={1}
                  max={5000}
                  value={form.max_pages}
                  onChange={(e) => set("max_pages", +e.target.value)}
                  className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-sm text-white focus:outline-none focus:border-emerald-500"
                />
              </div>
            </div>
            <div>
              <label className="text-sm text-gray-400 block mb-2">Excluded Paths (one per line)</label>
              <textarea
                rows={3}
                placeholder="/logout&#10;/static&#10;/cdn"
                value={form.excluded_paths}
                onChange={(e) => set("excluded_paths", e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-sm text-white font-mono placeholder-gray-500 focus:outline-none focus:border-emerald-500 resize-none"
              />
            </div>
            <div className="space-y-3">
              {[
                { key: "follow_subdomains", label: "Follow subdomains" },
                { key: "screenshot_pages", label: "Screenshot pages (for reports)" },
                { key: "analyze_source_maps", label: "Download & analyze source maps" },
              ].map(({ key, label }) => (
                <label key={key} className="flex items-center gap-3 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={(form as any)[key]}
                    onChange={(e) => set(key, e.target.checked)}
                    className="w-4 h-4 accent-emerald-500"
                  />
                  <span className="text-sm text-gray-300">{label}</span>
                </label>
              ))}
            </div>
          </div>
        )}

        {/* Step 3: Review */}
        {step === 3 && (
          <div className="space-y-4">
            <h2 className="text-lg font-semibold text-white mb-4">Review & Start</h2>
            <div className="space-y-2 text-sm">
              {[
                ["Target URL", form.target_url],
                ["Authentication", form.auth_method],
                ["Max Depth", form.max_depth],
                ["Max Pages", form.max_pages],
              ].map(([label, value]) => (
                <div key={String(label)} className="flex justify-between border-b border-gray-800 pb-2">
                  <span className="text-gray-500">{label}</span>
                  <span className="text-white font-medium">{String(value)}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* Navigation */}
      <div className="flex justify-between mt-6">
        <button
          onClick={() => setStep((s) => s - 1)}
          disabled={step === 0}
          className="flex items-center gap-2 text-sm text-gray-400 hover:text-white disabled:opacity-30 transition-colors"
        >
          <ChevronLeft className="w-4 h-4" /> Back
        </button>
        {step < STEPS.length - 1 ? (
          <button
            onClick={() => setStep((s) => s + 1)}
            disabled={!canNext()}
            className="flex items-center gap-2 bg-emerald-500 hover:bg-emerald-400 disabled:bg-gray-700 disabled:text-gray-500 text-black font-semibold px-5 py-2.5 rounded-lg text-sm transition-colors"
          >
            Next <ChevronRight className="w-4 h-4" />
          </button>
        ) : (
          <button
            onClick={submit}
            disabled={loading}
            className="flex items-center gap-2 bg-emerald-500 hover:bg-emerald-400 disabled:bg-gray-700 text-black font-semibold px-6 py-2.5 rounded-lg text-sm transition-colors"
          >
            {loading && <Loader2 className="w-4 h-4 animate-spin" />}
            Start Scan
          </button>
        )}
      </div>
    </div>
  );
}
