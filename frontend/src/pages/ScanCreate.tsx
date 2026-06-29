import { useQuery } from "@tanstack/react-query";
import clsx from "clsx";
import { Check, ChevronLeft, ChevronRight, Chrome, Cookie, Globe, Key, Loader2, ShieldCheck, SlidersHorizontal } from "lucide-react";
import { useState } from "react";
import toast from "react-hot-toast";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Button, Card, Field, PageHeader, PageShell, Select, TextArea, TextInput } from "../components/ui";
import { createScan, getProjects, startBrowserAuth } from "../lib/api";

type AuthMethod = "none" | "browser" | "cookies" | "bearer";

const STEPS = ["Target", "Auth", "Settings", "Review"];

const authMethods = [
  { value: "none", icon: Globe, label: "No Auth", desc: "Scan public pages and unauthenticated browser flows." },
  { value: "browser", icon: Chrome, label: "Browser Login", desc: "Capture an authenticated browser session before crawling." },
  { value: "cookies", icon: Cookie, label: "Cookie Import", desc: "Use DevTools JSON or Netscape cookie export for session replay." },
  { value: "bearer", icon: Key, label: "Bearer Token", desc: "Inject an Authorization header for API-heavy targets." },
] as const;

export function ScanCreate() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const [step, setStep] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [showPolicy, setShowPolicy] = useState(false);

  const [form, setForm] = useState({
    project_id: params.get("project") ?? "",
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
    policy_intensity: "careful",
    policy_max_pages: 15,
    policy_max_resources: 50,
    policy_max_depth: 1,
    policy_request_delay_ms: 500,
    policy_max_concurrency: 1,
    policy_same_origin_only: true,
    policy_allowed_hosts: "",
    policy_excluded_hosts: "",
    policy_authorization_confirmed: false,
  });

  const { data: projects = [], isLoading: projectsLoading } = useQuery({ queryKey: ["projects"], queryFn: getProjects });

  const set = (key: string, value: unknown) => {
    setError("");
    setForm((current) => ({ ...current, [key]: value }));
  };

  const validationError = () => {
    if (step === 0) {
      if (!form.project_id) return "Select a project before starting a scan.";
      if (!form.target_url) return "Enter the target URL.";
      if (!/^https?:\/\/.+/i.test(form.target_url)) return "Target URL must start with http:// or https://.";
    }
    if (step === 1) {
      if (form.auth_method === "bearer" && !form.bearer_token.trim()) return "Paste a bearer token or choose another authentication method.";
      if (form.auth_method === "cookies" && !form.cookies_json.trim()) return "Paste cookies or choose another authentication method.";
    }
    if (step === 2) {
      if (form.max_depth < 1 || form.max_depth > 20) return "Max depth must be between 1 and 20.";
      if (form.max_pages < 1 || form.max_pages > 5000) return "Max pages must be between 1 and 5000.";
      if (form.policy_max_pages < 1 || form.policy_max_pages > 500) return "Policy max pages must be between 1 and 500.";
      if (form.policy_max_resources < 1 || form.policy_max_resources > 1000) return "Policy max resources must be between 1 and 1000.";
      if (form.policy_max_concurrency < 1 || form.policy_max_concurrency > 6) return "Policy max concurrency must be between 1 and 6.";
    }
    return "";
  };

  const next = () => {
    const message = validationError();
    if (message) {
      setError(message);
      return;
    }
    setStep((current) => Math.min(current + 1, STEPS.length - 1));
  };

  const submit = async () => {
    const message = validationError();
    if (message) {
      setError(message);
      return;
    }

    setLoading(true);
    setError("");
    try {
      const excluded = form.excluded_paths
        .split("\n")
        .map((path) => path.trim())
        .filter(Boolean);
      const splitList = (value: string) =>
        value
          .split(/\n|,/)
          .map((item) => item.trim())
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
        scan_policy: {
          intensity: form.policy_intensity,
          max_pages: form.policy_max_pages,
          max_resources: form.policy_max_resources,
          max_depth: form.policy_max_depth,
          request_delay_ms: form.policy_request_delay_ms,
          max_concurrency: form.policy_max_concurrency,
          same_origin_only: form.policy_same_origin_only,
          allowed_hosts: splitList(form.policy_allowed_hosts),
          excluded_hosts: splitList(form.policy_excluded_hosts),
          excluded_paths: excluded,
          capture_screenshots: form.screenshot_pages,
          capture_storage: true,
          capture_api_flows: true,
          authorization_confirmed: form.policy_authorization_confirmed,
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
        toast.success("Browser authentication started");
      } else {
        toast.success("Scan started");
      }
      navigate(`/scans/${scan.id}`);
    } catch (err: any) {
      setError(err.response?.data?.detail ?? "Failed to create scan.");
      toast.error(err.response?.data?.detail ?? "Failed to create scan");
    } finally {
      setLoading(false);
    }
  };

  return (
    <PageShell className="max-w-4xl">
      <PageHeader title="New Scan" description="Configure target scope, authentication, crawl settings, and review before execution." />

      <div className="mb-6 grid gap-2 sm:grid-cols-4">
        {STEPS.map((label, index) => (
          <div key={label} className={clsx("rounded-lg border px-3 py-3", index === step ? "border-emerald-500/50 bg-emerald-500/10" : index < step ? "border-emerald-500/30 bg-slate-900" : "border-slate-800 bg-slate-900/60")}>
            <div className="flex items-center gap-2">
              <span className={clsx("flex h-6 w-6 items-center justify-center rounded-md text-xs font-semibold", index <= step ? "bg-emerald-500 text-slate-950" : "bg-slate-800 text-slate-500")}>
                {index < step ? <Check className="h-3.5 w-3.5" /> : index + 1}
              </span>
              <span className={clsx("text-sm font-semibold", index === step ? "text-white" : "text-slate-400")}>{label}</span>
            </div>
          </div>
        ))}
      </div>

      <Card className="p-5 sm:p-6">
        {error && <div className="mb-5 rounded-lg border border-red-900/70 bg-red-950/40 px-4 py-3 text-sm text-red-200">{error}</div>}

        {step === 0 && (
          <div className="grid gap-5">
            <div>
              <h2 className="text-lg font-semibold text-white">Target scope</h2>
              <p className="mt-1 text-sm text-slate-500">Choose the project and the root URL SSS should crawl.</p>
            </div>
            <Field label="Project">
              <Select value={form.project_id} onChange={(e) => set("project_id", e.target.value)} disabled={projectsLoading}>
                <option value="">Select a project</option>
                {projects.map((project: any) => (
                  <option key={project.id} value={project.id}>
                    {project.name}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="Target URL" hint="Use the container URL for local E2E scans, for example http://vulnerable-site.">
              <TextInput type="url" value={form.target_url} onChange={(e) => set("target_url", e.target.value)} placeholder="https://example.com" />
            </Field>
          </div>
        )}

        {step === 1 && (
          <div className="grid gap-5">
            <div>
              <h2 className="text-lg font-semibold text-white">Authentication</h2>
              <p className="mt-1 text-sm text-slate-500">Select how the crawler should access authenticated pages and API calls.</p>
            </div>
            <div className="grid gap-3 sm:grid-cols-2">
              {authMethods.map(({ value, icon: Icon, label, desc }) => (
                <button
                  key={value}
                  type="button"
                  onClick={() => set("auth_method", value)}
                  className={clsx(
                    "min-h-28 rounded-lg border p-4 text-left transition-colors",
                    form.auth_method === value ? "border-emerald-500/60 bg-emerald-500/10" : "border-slate-800 bg-slate-950/40 hover:border-slate-700"
                  )}
                >
                  <Icon className="mb-3 h-5 w-5 text-emerald-300" />
                  <div className="text-sm font-semibold text-white">{label}</div>
                  <p className="mt-1 text-xs leading-5 text-slate-500">{desc}</p>
                </button>
              ))}
            </div>
            {form.auth_method === "browser" && (
              <div className="rounded-lg border border-sky-500/30 bg-sky-500/10 p-4 text-sm leading-6 text-sky-200">
                SSS will open a controlled browser session. Complete login, then confirm capture so crawling can begin.
              </div>
            )}
            {form.auth_method === "bearer" && (
              <Field label="Bearer token" hint="Stored encrypted on the backend and injected only during the scan.">
                <TextInput type="password" value={form.bearer_token} onChange={(e) => set("bearer_token", e.target.value)} placeholder="eyJ... or token value" className="font-mono" />
              </Field>
            )}
            {form.auth_method === "cookies" && (
              <Field label="Cookies" hint="Accepts DevTools JSON array or Netscape cookie format.">
                <TextArea rows={7} value={form.cookies_json} onChange={(e) => set("cookies_json", e.target.value)} placeholder='[{"name":"session","value":"...","domain":"example.com"}]' className="font-mono" />
              </Field>
            )}
          </div>
        )}

        {step === 2 && (
          <div className="grid gap-5">
            <div>
              <h2 className="text-lg font-semibold text-white">Crawl settings</h2>
              <p className="mt-1 text-sm text-slate-500">Keep limits tight for MVP validation and expand scope only when needed.</p>
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="Max depth">
                <TextInput type="number" min={1} max={20} value={form.max_depth} onChange={(e) => set("max_depth", Number(e.target.value))} />
              </Field>
              <Field label="Max pages">
                <TextInput type="number" min={1} max={5000} value={form.max_pages} onChange={(e) => set("max_pages", Number(e.target.value))} />
              </Field>
            </div>
            <Field label="Excluded paths" hint="One path per line. Useful for logout, large media, or destructive flows.">
              <TextArea rows={4} value={form.excluded_paths} onChange={(e) => set("excluded_paths", e.target.value)} placeholder={"/logout\n/static\n/cdn"} className="font-mono" />
            </Field>
            <div className="grid gap-3">
              {[
                { key: "follow_subdomains", label: "Follow subdomains", desc: "Include discovered subdomains in scope when allowed." },
                { key: "screenshot_pages", label: "Capture screenshots", desc: "Attach page evidence for reports and manual review." },
                { key: "analyze_source_maps", label: "Analyze source maps", desc: "Download source maps when referenced by browser resources." },
              ].map(({ key, label, desc }) => (
                <label key={key} className="flex cursor-pointer items-start gap-3 rounded-lg border border-slate-800 bg-slate-950/40 p-4">
                  <input type="checkbox" checked={(form as any)[key]} onChange={(e) => set(key, e.target.checked)} className="mt-1 h-4 w-4 accent-emerald-500" />
                  <span>
                    <span className="block text-sm font-semibold text-white">{label}</span>
                    <span className="text-xs leading-5 text-slate-500">{desc}</span>
                  </span>
                </label>
              ))}
            </div>
            <div className="rounded-lg border border-slate-800 bg-slate-950/40">
              <button type="button" onClick={() => setShowPolicy((value) => !value)} className="flex w-full items-center justify-between gap-3 px-4 py-3 text-left">
                <span className="flex items-center gap-2 text-sm font-semibold text-white">
                  <SlidersHorizontal className="h-4 w-4 text-emerald-300" />
                  Advanced scan policy
                </span>
                <span className="text-xs text-slate-500">{showPolicy ? "Hide" : "Show"}</span>
              </button>
              {showPolicy && (
                <div className="grid gap-4 border-t border-slate-800 p-4">
                  <div className="grid gap-4 sm:grid-cols-3">
                    <Field label="Intensity">
                      <Select value={form.policy_intensity} onChange={(e) => set("policy_intensity", e.target.value)}>
                        <option value="careful">Careful</option>
                        <option value="low">Low</option>
                        <option value="normal">Normal</option>
                      </Select>
                    </Field>
                    <Field label="Policy max pages">
                      <TextInput type="number" min={1} max={500} value={form.policy_max_pages} onChange={(e) => set("policy_max_pages", Number(e.target.value))} />
                    </Field>
                    <Field label="Max resources">
                      <TextInput type="number" min={1} max={1000} value={form.policy_max_resources} onChange={(e) => set("policy_max_resources", Number(e.target.value))} />
                    </Field>
                    <Field label="Policy max depth">
                      <TextInput type="number" min={1} max={5} value={form.policy_max_depth} onChange={(e) => set("policy_max_depth", Number(e.target.value))} />
                    </Field>
                    <Field label="Request delay ms">
                      <TextInput type="number" min={100} max={5000} value={form.policy_request_delay_ms} onChange={(e) => set("policy_request_delay_ms", Number(e.target.value))} />
                    </Field>
                    <Field label="Max concurrency">
                      <TextInput type="number" min={1} max={6} value={form.policy_max_concurrency} onChange={(e) => set("policy_max_concurrency", Number(e.target.value))} />
                    </Field>
                  </div>
                  <div className="grid gap-4 sm:grid-cols-2">
                    <Field label="Allowed hosts" hint="Comma or newline separated. Target host is added automatically.">
                      <TextArea rows={3} value={form.policy_allowed_hosts} onChange={(e) => set("policy_allowed_hosts", e.target.value)} placeholder="example.com" className="font-mono" />
                    </Field>
                    <Field label="Excluded hosts">
                      <TextArea rows={3} value={form.policy_excluded_hosts} onChange={(e) => set("policy_excluded_hosts", e.target.value)} placeholder="cdn.example.net" className="font-mono" />
                    </Field>
                  </div>
                  <label className="flex cursor-pointer items-start gap-3 rounded-lg border border-slate-800 bg-slate-950/60 p-4">
                    <input type="checkbox" checked={form.policy_same_origin_only} onChange={(e) => set("policy_same_origin_only", e.target.checked)} className="mt-1 h-4 w-4 accent-emerald-500" />
                    <span>
                      <span className="block text-sm font-semibold text-white">Same origin only</span>
                      <span className="text-xs leading-5 text-slate-500">Block redirects and discovered links outside the target origin unless explicitly allowed by policy.</span>
                    </span>
                  </label>
                  <label className="flex cursor-pointer items-start gap-3 rounded-lg border border-amber-500/30 bg-amber-500/10 p-4">
                    <input type="checkbox" checked={form.policy_authorization_confirmed} onChange={(e) => set("policy_authorization_confirmed", e.target.checked)} className="mt-1 h-4 w-4 accent-amber-400" />
                    <span>
                      <span className="block text-sm font-semibold text-amber-100">Authorization confirmed</span>
                      <span className="text-xs leading-5 text-amber-200/80">Confirm that you are authorized to scan the target and selected scope.</span>
                    </span>
                  </label>
                </div>
              )}
            </div>
          </div>
        )}

        {step === 3 && (
          <div className="grid gap-5">
            <div>
              <h2 className="text-lg font-semibold text-white">Review</h2>
              <p className="mt-1 text-sm text-slate-500">Confirm the scan configuration before queueing the job.</p>
            </div>
            <div className="grid gap-3">
              {[
                ["Target URL", form.target_url],
                ["Authentication", authMethods.find((method) => method.value === form.auth_method)?.label ?? form.auth_method],
                ["Max depth", form.max_depth],
                ["Max pages", form.max_pages],
                ["Policy intensity", form.policy_intensity],
                ["Policy limits", `${form.policy_max_pages} pages / ${form.policy_max_resources} resources / depth ${form.policy_max_depth}`],
                ["Authorization confirmed", form.policy_authorization_confirmed ? "Yes" : "No"],
                ["Source maps", form.analyze_source_maps ? "Enabled" : "Disabled"],
              ].map(([label, value]) => (
                <div key={String(label)} className="grid gap-2 rounded-lg border border-slate-800 bg-slate-950/40 p-4 sm:grid-cols-[160px_1fr]">
                  <span className="text-sm text-slate-500">{label}</span>
                  <span className="break-words text-sm font-medium text-white">{String(value)}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </Card>

      <div className="mt-6 flex items-center justify-between">
        <Button variant="ghost" onClick={() => setStep((current) => Math.max(current - 1, 0))} disabled={step === 0}>
          <ChevronLeft className="h-4 w-4" />
          Back
        </Button>
        {step < STEPS.length - 1 ? (
          <Button onClick={next}>
            Next
            <ChevronRight className="h-4 w-4" />
          </Button>
        ) : (
          <Button onClick={submit} disabled={loading}>
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldCheck className="h-4 w-4" />}
            Start Scan
          </Button>
        )}
      </div>
    </PageShell>
  );
}
