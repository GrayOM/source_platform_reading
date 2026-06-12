import { useEffect, useRef, useState } from "react";

interface ScanProgress {
  scan_id: string;
  phase: string | null;
  progress: number;
  pages_discovered?: number;
  resources_collected?: number;
  findings_count?: number;
  message?: string;
}

export function useScanProgress(scanId: string | undefined, enabled: boolean = true) {
  const [progress, setProgress] = useState<ScanProgress | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    if (!scanId || !enabled) return;

    const token = localStorage.getItem("access_token");
    const wsBase = import.meta.env.VITE_WS_URL ?? `ws://${window.location.host}`;
    const url = `${wsBase}/ws/scans/${scanId}?token=${token}`;

    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onmessage = (ev) => {
      try {
        const data: ScanProgress = JSON.parse(ev.data);
        setProgress(data);
      } catch {}
    };

    ws.onerror = () => ws.close();

    return () => {
      ws.close();
      wsRef.current = null;
    };
  }, [scanId, enabled]);

  return progress;
}
