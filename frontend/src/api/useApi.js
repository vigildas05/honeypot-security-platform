import { useCallback, useEffect, useRef, useState } from "react";

/**
 * Load data, optionally re-polling. Returns { data, error, loading, reload }.
 * @template T
 * @param {() => Promise<T>} loader
 * @param {unknown[]} deps
 * @param {{ pollMs?: number }} [options]
 */
export function useApi(loader, deps, { pollMs } = {}) {
  const [data, setData] = useState(/** @type {T | null} */ (null));
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const loaderRef = useRef(loader);
  loaderRef.current = loader;

  const reload = useCallback(async () => {
    try {
      const result = await loaderRef.current();
      setData(result);
      setError("");
    } catch (e) {
      setError(e instanceof Error ? e.message : "Request failed");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    setLoading(true);
    reload();
    if (!pollMs) return undefined;
    const timer = setInterval(reload, pollMs);
    return () => clearInterval(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, pollMs, reload]);

  return { data, error, loading, reload };
}
