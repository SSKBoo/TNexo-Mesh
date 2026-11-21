import { useEffect, useState } from "react";
import { isMock, probeBridge } from "./core/bridge.ts";

export default function App() {
  const [mock, setMock] = useState(isMock);

  useEffect(() => {
    probeBridge().then(() => setMock(isMock));
  }, []);

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 p-6">
      {mock && (
        <div className="mb-4 inline-block rounded bg-amber-500/20 px-3 py-1 text-amber-300 text-sm">
          Datos de demostración
        </div>
      )}
      <h1 className="text-2xl font-bold">NexoMesh</h1>
      <p className="text-slate-400">Panel de control</p>
    </div>
  );
}
