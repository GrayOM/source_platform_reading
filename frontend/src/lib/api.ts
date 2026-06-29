import axios from "axios";

const BASE = import.meta.env.VITE_API_URL ?? "/api/v1";

export const api = axios.create({ baseURL: BASE });

api.interceptors.request.use((cfg) => {
  const token = localStorage.getItem("access_token");
  if (token) cfg.headers.Authorization = `Bearer ${token}`;
  return cfg;
});

api.interceptors.response.use(
  (r) => r,
  async (err) => {
    if (err.response?.status === 401 && !err.config._retry) {
      err.config._retry = true;
      const refresh = localStorage.getItem("refresh_token");
      if (refresh) {
        try {
          const { data } = await axios.post(`${BASE}/auth/refresh`, { refresh_token: refresh });
          localStorage.setItem("access_token", data.access_token);
          localStorage.setItem("refresh_token", data.refresh_token);
          err.config.headers.Authorization = `Bearer ${data.access_token}`;
          return api(err.config);
        } catch {
          localStorage.clear();
          window.location.href = "/login";
        }
      }
    }
    return Promise.reject(err);
  }
);

// Auth
export const login = (email: string, password: string) =>
  api.post("/auth/login", { email, password }).then((r) => r.data);
export const register = (email: string, password: string, full_name: string) =>
  api.post("/auth/register", { email, password, full_name }).then((r) => r.data);
export const getMe = () => api.get("/auth/me").then((r) => r.data);

// Projects
export const getProjects = () => api.get("/projects").then((r) => r.data);
export const createProject = (data: { name: string; description?: string }) =>
  api.post("/projects", data).then((r) => r.data);
export const deleteProject = (id: string) => api.delete(`/projects/${id}`);

// Scans
export const getScans = (project_id?: string) =>
  api.get("/scans", { params: { project_id, limit: 50 } }).then((r) => r.data);
export const getScan = (id: string) => api.get(`/scans/${id}`).then((r) => r.data);
export const createScan = (data: object) => api.post("/scans", data).then((r) => r.data);
export const cancelScan = (id: string) => api.post(`/scans/${id}/cancel`);
export const startBrowserAuth = (id: string) =>
  api.post(`/scans/${id}/browser-auth/start`).then((r) => r.data);
export const getDiffCandidates = (scan_id: string) =>
  api.get(`/scans/${scan_id}/diff-candidates`).then((r) => r.data);
export const compareScans = (base_scan_id: string, compare_scan_id: string) =>
  api.post("/scans/compare", { base_scan_id, compare_scan_id }).then((r) => r.data);

// Findings
export const getFindings = (scan_id?: string, severity?: string, triage_status?: string, recurrence_filter?: string) =>
  api
    .get("/findings", {
      params: {
        scan_id,
        severity,
        triage_status,
        only_new: recurrence_filter === "only_new" || undefined,
        recurring: recurrence_filter === "recurring" || undefined,
        previously_verified: recurrence_filter === "previously_verified" || undefined,
        previously_false_positive: recurrence_filter === "previously_false_positive" || undefined,
        limit: 200,
      },
    })
    .then((r) => r.data);
export const updateFinding = (id: string, data: object) =>
  api.patch(`/findings/${id}`, data).then((r) => r.data);
export const updateFindingTriage = (id: string, data: object) =>
  api.patch(`/findings/${id}/triage`, data).then((r) => r.data);
export const getFindingArtifacts = (finding_id: string) =>
  api.get(`/findings/${finding_id}/artifacts`).then((r) => r.data);
export const getScanArtifacts = (scan_id: string, params?: { artifact_type?: string; auth_context?: string }) =>
  api.get(`/scans/${scan_id}/artifacts`, { params }).then((r) => r.data);

// Reports
export const getScanReports = (scan_id: string) =>
  api.get(`/reports/scans/${scan_id}`).then((r) => r.data);
export const generateReport = (scan_id: string, format: string, report_type: string, compare_scan_id?: string, report_metadata?: object) =>
  api.post(`/reports/scans/${scan_id}/generate`, { format, report_type, compare_scan_id, report_metadata }).then((r) => r.data);
export const downloadReport = async (report_id: string) => {
  const response = await api.get(`/reports/${report_id}/download`, { responseType: "blob" });
  const disposition = response.headers["content-disposition"] ?? "";
  const match = disposition.match(/filename="?([^"]+)"?/i);
  const filename = match?.[1] ?? `sss-report-${report_id}`;
  const url = URL.createObjectURL(response.data);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
};
