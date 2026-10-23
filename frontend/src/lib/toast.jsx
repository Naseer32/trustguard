import { createContext, useCallback, useContext, useMemo, useRef, useState } from "react";
import { Icon } from "../ui/Icon.jsx";

const Ctx = createContext(null);
export const useToast = () => useContext(Ctx);

export function ToastProvider({ children }) {
  const [items, setItems] = useState([]);
  const seq = useRef(0);

  const dismiss = useCallback((id) => setItems((l) => l.filter((t) => t.id !== id)), []);
  const push = useCallback((kind, title, body) => {
    const id = ++seq.current;
    setItems((l) => [...l.slice(-3), { id, kind, title, body }]);
    setTimeout(() => dismiss(id), kind === "error" ? 9000 : 5500);
  }, [dismiss]);

  const api = useMemo(() => ({
    success: (t, b) => push("success", t, b),
    error: (t, b) => push("error", t, b),
    info: (t, b) => push("info", t, b),
  }), [push]);

  return (
    <Ctx.Provider value={api}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {items.map((t) => (
          <div key={t.id} className={"toast " + t.kind}>
            <Icon name={t.kind === "error" ? "alert" : t.kind === "success" ? "check" : "info"} />
            <div>
              <strong>{t.title}</strong>
              {t.body && <p>{t.body}</p>}
            </div>
            <button className="icon-btn" aria-label="Dismiss" onClick={() => dismiss(t.id)}><Icon name="x" /></button>
          </div>
        ))}
      </div>
    </Ctx.Provider>
  );
}
