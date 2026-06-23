import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ChevronRight, FolderOpen, Loader2, Plus, Trash2 } from "lucide-react";
import { useState } from "react";
import toast from "react-hot-toast";
import { Link } from "react-router-dom";
import { Button, Card, EmptyState, Field, PageHeader, PageShell, TextArea, TextInput } from "../components/ui";
import { createProject, deleteProject, getProjects } from "../lib/api";

export function Projects() {
  const qc = useQueryClient();
  const [showNew, setShowNew] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [formError, setFormError] = useState("");

  const { data: projects = [], isLoading } = useQuery({ queryKey: ["projects"], queryFn: getProjects });

  const createMutation = useMutation({
    mutationFn: () => createProject({ name: name.trim(), description: description.trim() || undefined }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["projects"] });
      setShowNew(false);
      setName("");
      setDescription("");
      setFormError("");
      toast.success("Project created");
    },
    onError: (err: any) => setFormError(err.response?.data?.detail ?? "Failed to create project"),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteProject(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["projects"] });
      toast.success("Project deleted");
    },
    onError: () => toast.error("Failed to delete project"),
  });

  const submit = () => {
    if (!name.trim()) {
      setFormError("Project name is required.");
      return;
    }
    createMutation.mutate();
  };

  return (
    <PageShell className="max-w-5xl">
      <PageHeader
        title="Projects"
        description="Group assessments by application, client, environment, or testing scope."
        action={
          <Button onClick={() => setShowNew((value) => !value)}>
            <Plus className="h-4 w-4" />
            New Project
          </Button>
        }
      />

      {showNew && (
        <Card className="mb-6 p-5">
          <div className="mb-4">
            <h2 className="font-semibold text-white">Create project</h2>
            <p className="mt-1 text-sm text-slate-500">Use a clear scope name so scan results and reports stay organized.</p>
          </div>
          <div className="grid gap-4">
            <Field label="Project name" error={formError}>
              <TextInput value={name} onChange={(e) => setName(e.target.value)} placeholder="Production web app" />
            </Field>
            <Field label="Description" hint="Optional context such as target scope, owner, or environment.">
              <TextArea rows={3} value={description} onChange={(e) => setDescription(e.target.value)} placeholder="External assessment scope for the public web application." />
            </Field>
            <div className="flex flex-wrap gap-2">
              <Button onClick={submit} disabled={createMutation.isPending}>
                {createMutation.isPending && <Loader2 className="h-4 w-4 animate-spin" />}
                Create project
              </Button>
              <Button variant="secondary" onClick={() => setShowNew(false)}>
                Cancel
              </Button>
            </div>
          </div>
        </Card>
      )}

      {isLoading ? (
        <Card className="p-8 text-sm text-slate-500">Loading projects...</Card>
      ) : projects.length === 0 ? (
        <EmptyState
          icon={<FolderOpen className="h-10 w-10" />}
          title="No projects yet"
          description="Create a project first, then start a scan from that scope."
          action={
            <Button onClick={() => setShowNew(true)}>
              <Plus className="h-4 w-4" />
              Create project
            </Button>
          }
        />
      ) : (
        <div className="grid gap-3">
          {projects.map((project: any) => (
            <Card key={project.id} className="group p-5 transition-colors hover:border-slate-700">
              <div className="grid gap-4 sm:grid-cols-[1fr_auto] sm:items-center">
                <div className="min-w-0">
                  <div className="flex items-center gap-3">
                    <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/10 p-2">
                      <FolderOpen className="h-4 w-4 text-emerald-300" />
                    </div>
                    <div className="min-w-0">
                      <h3 className="truncate text-sm font-semibold text-white">{project.name}</h3>
                      <p className="mt-0.5 truncate text-xs text-slate-500">{project.description || "No description"}</p>
                    </div>
                  </div>
                </div>
                <div className="flex flex-wrap items-center gap-2 sm:justify-end">
                  <span className="rounded-md border border-slate-800 bg-slate-950/60 px-2.5 py-1 text-xs font-semibold text-slate-300">
                    {project.scan_count ?? 0} scans
                  </span>
                  <Link to={`/scans/new?project=${project.id}`} className="rounded-lg px-3 py-2 text-xs font-semibold text-emerald-300 hover:bg-slate-800 hover:text-emerald-200">
                    New scan
                  </Link>
                  <button
                    onClick={() => {
                      if (confirm(`Delete "${project.name}"?`)) deleteMutation.mutate(project.id);
                    }}
                    className="rounded-lg p-2 text-slate-500 transition-colors hover:bg-red-950/40 hover:text-red-300"
                    aria-label={`Delete ${project.name}`}
                  >
                    <Trash2 className="h-4 w-4" />
                  </button>
                  <ChevronRight className="hidden h-4 w-4 text-slate-700 sm:block" />
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}
    </PageShell>
  );
}
