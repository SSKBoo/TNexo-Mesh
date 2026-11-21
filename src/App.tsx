import { useCallback, useEffect, useState } from "react";
import { bridge, isMock, type BridgeStatus } from "./core/bridge.ts";

export default function App() {
  const [mock, setMock] = useState(true);
  const [status, setStatus] = useState<BridgeStatus>({ ok: false });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [lastCommand, setLastCommand] = useState("");

  const refresh = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const wasMock = await bridge.probe();
      setMock(wasMock);
      setStatus(wasMock ? { ok: false } : await bridge.getStatus());
    } catch (e) {
      setError(String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const sendCommand = async (command: string) => {
    try {
      const result = await bridge.sendCommand(command);
      setLastCommand(`${command}: ${result.ok ? "OK" : result.error ?? "error"}`);
      await refresh();
    } catch (e) {
      setError(String(e));
    }
  };

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-6">
      {isMock && (
        <div className="mb-4 inline-block rounded bg-amber-500/20 px-3 py-1 text-amber-300 text-sm">
          Datos de demostración
        </div>
      )}

      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold">NexoMesh</h1>
          <p className="text-slate-400">Panel de control</p>
        </div>
        <button
          onClick={refresh}
          className="rounded bg-slate-700 px-3 py-2 text-sm hover:bg-slate-600"
        >
          Actualizar
        </button>
      </div>

      {loading ? (
        <p className="mt-6 text-slate-400">Conectando con el bridge local…</p>
      ) : error ? (
        <p className="mt-6 text-red-400">Error: {error}</p>
      ) : (
        <>
          <div className="mt-6 grid grid-cols-2 gap-4 sm:grid-cols-4">
            <div className="rounded border border-slate-700 p-4">
              <div className="text-xs text-slate-400">Bridge</div>
              <div className={mock ? "text-amber-300" : "text-emerald-300"}>
                {mock ? "Demostración" : "Conectado"}
              </div>
            </div>
            <div className="rounded border border-slate-700 p-4">
              <div className="text-xs text-slate-400">Pares</div>
              <div className="text-xl">{status.peers ?? "—"}</div>
            </div>
            <div className="rounded border border-slate-700 p-4">
              <div className="text-xs text-slate-400">IP virtual</div>
              <div className="text-xl">{status.virtualIp ?? "—"}</div>
            </div>
            <div className="rounded border border-slate-700 p-4">
              <div className="text-xs text-slate-400">Túnel</div>
              <div className={status.ok ? "text-emerald-300" : "text-slate-400"}>
                {status.ok ? "Activo" : "Inactivo"}
              </div>
            </div>
          </div>

          <div className="mt-6 flex gap-3">
            <button
              onClick={() => sendCommand("status")}
              className="rounded bg-emerald-600 px-4 py-2 text-sm hover:bg-emerald-500"
            >
              Estado
            </button>
            <button
              onClick={() => sendCommand("peers")}
              className="rounded bg-sky-600 px-4 py-2 text-sm hover:bg-sky-500"
            >
              Pares
            </button>
          </div>
          {lastCommand && <p className="mt-3 text-sm text-slate-400">{lastCommand}</p>}
        </>
      )}
    </div>
  );
}
