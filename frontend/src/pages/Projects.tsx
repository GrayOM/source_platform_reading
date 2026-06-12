import { useState } from "react";
import { Link } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { Plus, FolderOpen, Trash2, ChevronRight, Search } from "lucide-react";
import toast from "react-hot-toast";
import { getProjects, createProject, deleteProject, getScans } from "../lib/api";

export function Projects() {
  const qc = useQueryClient();
  const [showNew, setShowNew] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");

  const { data: projects = [] } = useQuery({ queryKey: ["projects"], queryFn: getProjects });

  const createMutation = useMutation({
    mutationFn: () => createProject({ name, description }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["projects"] });
      setShowNew(false);
      setName("");
      setDescription("");
      toast.success("Project created");
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => deleteProject(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["projects"] });
      toast.success("Project deleted");
    },
  });

  return (
    <div className="p-8 max-w-4xl mx-auto">
      <div className="flex items-center justify-between mb-8">
        <h1 className="text-2xl font-bold text-white">Projects</h1>
        <button
          onClick={() => setShowNew(true)}
          className="flex items-center gap-2 bg-emerald-500 hover:bg-emerald-400 text-black font-semibold px-4 py-2 rounded-lg text-sm transition-colors"
        >
          <Plus className="w-4 h-4" /> New Project
        </button>
      </div>

      {showNew && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-6 mb-6">
          <h2 className="text-sm font-semibold text-white mb-4">New Project</h2>
          <div className="space-y-3">
            <input
              type="text"
              placeholder="Project name"
              value={name}
              onChange={(e) => setName(e.target.value)}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-emerald-500"
            />
            <input
              type="text"
              placeholder="Description (optional)"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              className="w-full bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-emerald-500"
            />
            <div className="flex gap-2">
              <button
                onClick={() => createMutation.mutate()}
                disabled={!name || createMutation.isPending}
                className="bg-emerald-500 hover:bg-emerald-400 disabled:bg-gray-700 text-black font-semibold px-4 py-2 rounded-lg text-sm transition-colors"
              >
                Create
              </button>
              <button
                onClick={() => setShowNew(false)}
                className="bg-gray-800 hover:bg-gray-700 text-gray-300 px-4 py-2 rounded-lg text-sm transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}

      <div className="space-y-3">
        {projects.length === 0 ? (
          <div className="text-center py-16 text-gray-500">
            <FolderOpen className="w-10 h-10 mx-auto mb-3 opacity-30" />
            <p>No projects yet. Create one to get started.</p>
          </div>
        ) : (
          projects.map((p: any) => (
            <div
              key={p.id}
              className="group flex items-center gap-4 bg-gray-900 border border-gray-800 rounded-xl p-5 hover:border-gray-700 transition-colors"
            >
              <FolderOpen className="w-5 h-5 text-emerald-400 shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="text-sm font-medium text-white">{p.name}</div>
                {p.description && (
                  <div className="text-xs text-gray-500 mt-0.5 truncate">{p.description}</div>
                )}
                <div className="text-xs text-gray-600 mt-1">{p.scan_count} scans</div>
              </div>
              <Link
                to={`/scans/new?project=${p.id}`}
                className="opacity-0 group-hover:opacity-100 text-xs text-emerald-400 hover:underline transition-opacity shrink-0"
              >
                + Scan
              </Link>
              <button
                onClick={() => {
                  if (confirm(`Delete "${p.name}"?`)) deleteMutation.mutate(p.id);
                }}
                className="opacity-0 group-hover:opacity-100 p-1.5 text-gray-600 hover:text-red-400 transition-all"
              >
                <Trash2 className="w-4 h-4" />
              </button>
              <ChevronRight className="w-4 h-4 text-gray-700" />
            </div>
          ))
        )}
      </div>
    </div>
  );
}
