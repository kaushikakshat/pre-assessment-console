import { useCallback, useEffect, useRef, useState } from 'react';
import { api, ApiError } from './api';

const RETRY_MS = 5000;

/** GET `path` (null = idle). Keeps previous data while refreshing; `pollMs(data)` > 0 schedules the next refresh. */

export function useLoad<T>(path: string | null, pollMs?: (d: T) => number) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [tick, setTick] = useState(0);
  const [stalled, setStalled] = useState(false);
  const dataRef = useRef<T | null>(null);
  dataRef.current = data;
  const poll = useRef(pollMs);
  poll.current = pollMs;
  useEffect(() => {
    if (!path) return;
    let dead = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const run = async () => {
      try {
        const d = await api<T>(path);
        if (dead) return;
        setData(d); setError(null); setStalled(false);
        const ms = poll.current?.(d);
        if (ms) timer = setTimeout(run, ms);
      } catch (e) {
        if (dead) return;
        setError(e instanceof ApiError ? e : new ApiError(0, 'Something went wrong. Try again.'));
        // A failed poll must not freeze live updates: keep the old data, flag it, retry.
        if (poll.current && dataRef.current) { setStalled(true); timer = setTimeout(run, RETRY_MS); }
      }
    };
    run();
    return () => { dead = true; clearTimeout(timer); };
  }, [path, tick]);
  const reload = useCallback(() => setTick((t) => t + 1), []);
  return { data, error, stalled, reload, loading: path !== null && !data && !error };
}
