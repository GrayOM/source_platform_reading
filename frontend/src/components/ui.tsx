import clsx from "clsx";
import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode, SelectHTMLAttributes, TextareaHTMLAttributes } from "react";

export function PageShell({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={clsx("mx-auto w-full max-w-6xl px-4 py-6 sm:px-6 lg:px-8", className)}>{children}</div>;
}

export function PageHeader({
  title,
  description,
  action,
}: {
  title: string;
  description?: string;
  action?: ReactNode;
}) {
  return (
    <div className="mb-6 flex flex-col gap-4 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <h1 className="text-2xl font-semibold tracking-normal text-white">{title}</h1>
        {description && <p className="mt-1 max-w-2xl text-sm leading-6 text-slate-400">{description}</p>}
      </div>
      {action}
    </div>
  );
}

export function Card({ children, className }: { children: ReactNode; className?: string }) {
  return <div className={clsx("rounded-lg border border-slate-800 bg-slate-900/80 shadow-sm", className)}>{children}</div>;
}

export function Button({
  children,
  className,
  variant = "primary",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: "primary" | "secondary" | "ghost" | "danger" }) {
  const variants = {
    primary: "bg-emerald-500 text-slate-950 hover:bg-emerald-400 disabled:bg-slate-700 disabled:text-slate-500",
    secondary: "border border-slate-700 bg-slate-800 text-slate-100 hover:bg-slate-700 disabled:text-slate-500",
    ghost: "text-slate-400 hover:bg-slate-800 hover:text-white disabled:text-slate-600",
    danger: "border border-red-900/70 bg-red-950/40 text-red-300 hover:bg-red-950",
  };

  return (
    <button
      className={clsx(
        "inline-flex items-center justify-center gap-2 rounded-lg px-4 py-2.5 text-sm font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-emerald-400/60 disabled:cursor-not-allowed",
        variants[variant],
        className
      )}
      {...props}
    >
      {children}
    </button>
  );
}

export function TextInput({ className, ...props }: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      className={clsx(
        "w-full rounded-lg border border-slate-700 bg-slate-950/60 px-3.5 py-2.5 text-sm text-white placeholder-slate-500 outline-none transition-colors focus:border-emerald-400",
        className
      )}
      {...props}
    />
  );
}

export function TextArea({ className, ...props }: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      className={clsx(
        "w-full rounded-lg border border-slate-700 bg-slate-950/60 px-3.5 py-2.5 text-sm text-white placeholder-slate-500 outline-none transition-colors focus:border-emerald-400",
        className
      )}
      {...props}
    />
  );
}

export function Select({ className, ...props }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      className={clsx(
        "w-full rounded-lg border border-slate-700 bg-slate-950/60 px-3.5 py-2.5 text-sm text-white outline-none transition-colors focus:border-emerald-400",
        className
      )}
      {...props}
    />
  );
}

export function Field({
  label,
  hint,
  error,
  children,
}: {
  label: string;
  hint?: string;
  error?: string;
  children: ReactNode;
}) {
  return (
    <label className="block">
      <span className="mb-2 block text-sm font-medium text-slate-300">{label}</span>
      {children}
      {hint && !error && <span className="mt-1.5 block text-xs leading-5 text-slate-500">{hint}</span>}
      {error && <span className="mt-1.5 block text-xs leading-5 text-red-300">{error}</span>}
    </label>
  );
}

const severityClasses: Record<string, string> = {
  critical: "border-red-500/40 bg-red-500/15 text-red-200",
  high: "border-orange-500/40 bg-orange-500/15 text-orange-200",
  medium: "border-yellow-500/40 bg-yellow-500/15 text-yellow-100",
  low: "border-emerald-500/40 bg-emerald-500/15 text-emerald-200",
  info: "border-sky-500/40 bg-sky-500/15 text-sky-200",
};

export function Badge({ children, tone = "neutral" }: { children: ReactNode; tone?: string }) {
  return (
    <span
      className={clsx(
        "inline-flex max-w-full items-center rounded-md border px-2 py-1 text-xs font-semibold uppercase tracking-normal",
        severityClasses[tone] ?? "border-slate-700 bg-slate-800 text-slate-300"
      )}
    >
      {children}
    </span>
  );
}

export function EmptyState({ icon, title, description, action }: { icon: ReactNode; title: string; description?: string; action?: ReactNode }) {
  return (
    <div className="flex min-h-48 flex-col items-center justify-center rounded-lg border border-dashed border-slate-800 bg-slate-900/40 px-6 py-10 text-center">
      <div className="mb-3 text-slate-500">{icon}</div>
      <h3 className="text-sm font-semibold text-white">{title}</h3>
      {description && <p className="mt-1 max-w-md text-sm leading-6 text-slate-500">{description}</p>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function CodeBlock({ children, tone = "default" }: { children: ReactNode; tone?: "default" | "blue" | "green" }) {
  const toneClass = tone === "blue" ? "text-sky-200" : tone === "green" ? "text-emerald-200" : "text-slate-200";
  return (
    <pre className={clsx("max-h-96 overflow-auto whitespace-pre-wrap break-words rounded-lg border border-slate-800 bg-slate-950 p-4 text-xs leading-5", toneClass)}>
      {children}
    </pre>
  );
}
