import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { AlertCircle, CheckCircle2, Loader2, Shield } from "lucide-react";
import toast from "react-hot-toast";
import { login, register } from "../lib/api";
import { Button, Card, Field, TextInput } from "../components/ui";

export function Login() {
  const navigate = useNavigate();
  const [mode, setMode] = useState<"login" | "register">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [fullName, setFullName] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      if (mode === "login") {
        const data = await login(email, password);
        localStorage.setItem("access_token", data.access_token);
        localStorage.setItem("refresh_token", data.refresh_token);
        toast.dismiss();
        navigate("/");
      } else {
        await register(email, password, fullName);
        toast.success("Account created! Please log in.");
        setMode("login");
      }
    } catch (err: any) {
      const message = err.response?.data?.detail ?? "Unable to complete the request. Check your credentials and try again.";
      setError(message);
      toast.error(message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-slate-950 px-4 py-8 text-slate-100">
      <div className="mx-auto grid min-h-[calc(100vh-4rem)] w-full max-w-6xl items-center gap-8 lg:grid-cols-[1.1fr_0.9fr]">
        <section className="hidden lg:block">
          <div className="mb-6 inline-flex items-center gap-3 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-2 text-sm font-semibold text-emerald-200">
            <Shield className="h-4 w-4" />
            Browser-first security assessment
          </div>
          <h1 className="max-w-2xl text-4xl font-semibold leading-tight text-white">SSS Platform</h1>
          <p className="mt-4 max-w-xl text-base leading-7 text-slate-400">
            Collect browser-accessible web resources and API flows, review deterministic findings, and export reports for security assessment workflows.
          </p>
          <div className="mt-8 grid max-w-xl gap-3">
            {[
              "DOM XSS, storage, postMessage, source map, API endpoint, and secret candidates",
              "Authenticated crawling with browser login, cookies, or bearer tokens",
              "HTML, Markdown, and JSON reports with PoC and reproduction steps",
            ].map((item) => (
              <div key={item} className="flex items-start gap-3 rounded-lg border border-slate-800 bg-slate-900/70 p-4">
                <CheckCircle2 className="mt-0.5 h-4 w-4 flex-shrink-0 text-emerald-300" />
                <p className="text-sm leading-6 text-slate-300">{item}</p>
              </div>
            ))}
          </div>
        </section>

        <div className="mx-auto w-full max-w-md">
          <div className="mb-6 text-center lg:hidden">
            <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-lg border border-emerald-500/30 bg-emerald-500/10">
              <Shield className="h-6 w-6 text-emerald-300" />
            </div>
            <h1 className="text-2xl font-semibold text-white">SSS Platform</h1>
            <p className="mt-1 text-sm text-slate-500">Browser-first security assessment</p>
          </div>

          <Card className="p-6 sm:p-8">
            <div className="mb-6">
              <h2 className="text-xl font-semibold text-white">{mode === "login" ? "Sign in" : "Create account"}</h2>
              <p className="mt-1 text-sm text-slate-500">
                {mode === "login" ? "Continue to your assessment workspace." : "Create a workspace account to start scans."}
              </p>
            </div>

            {error && (
              <div className="mb-4 flex gap-2 rounded-lg border border-red-900/70 bg-red-950/40 p-3 text-sm text-red-200">
                <AlertCircle className="mt-0.5 h-4 w-4 flex-shrink-0" />
                <span>{error}</span>
              </div>
            )}

            <form onSubmit={submit} className="space-y-4">
            {mode === "register" && (
              <Field label="Full name">
                <TextInput type="text" placeholder="Security Analyst" value={fullName} onChange={(e) => setFullName(e.target.value)} required />
              </Field>
            )}
            <Field label="Email">
              <TextInput type="email" placeholder="analyst@example.com" value={email} onChange={(e) => setEmail(e.target.value)} required />
            </Field>
            <Field label="Password" hint={mode === "register" ? "Use at least 8 characters." : undefined}>
              <TextInput type="password" placeholder="Password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength={8} />
            </Field>
            <Button type="submit" disabled={loading} className="w-full">
              {loading && <Loader2 className="h-4 w-4 animate-spin" />}
              {mode === "login" ? "Sign in" : "Create account"}
            </Button>
          </form>
          <p className="mt-5 text-center text-sm text-slate-500">
            {mode === "login" ? "No account? " : "Have an account? "}
            <button
              className="font-semibold text-emerald-300 hover:text-emerald-200"
              onClick={() => {
                setError("");
                setMode(mode === "login" ? "register" : "login");
              }}
            >
              {mode === "login" ? "Register" : "Sign in"}
            </button>
          </p>
        </Card>
        </div>
      </div>
    </div>
  );
}
