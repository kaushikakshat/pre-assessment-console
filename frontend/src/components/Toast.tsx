import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from 'react';
import { Icon } from './Icon';

interface ToastItem { id: number; text: string }
const Ctx = createContext<(text: string) => void>(() => {});
export const useToast = () => useContext(Ctx);

const MAX = 3;
const LIFETIME_MS = 4000;

export function ToastProvider({ children }: { children: ReactNode }) {
  const [items, setItems] = useState<ToastItem[]>([]);
  const next = useRef(0);
  const toast = useCallback((text: string) => {
    const id = next.current++;
    setItems((x) => [...x, { id, text }].slice(-MAX));
    setTimeout(() => setItems((x) => x.filter((t) => t.id !== id)), LIFETIME_MS);
  }, []);
  return (
    <Ctx.Provider value={toast}>
      {children}
      <div className="toasts" role="status" aria-live="polite">
        {items.map((t) => <div key={t.id} className="toast"><Icon name="check" size={14} />{t.text}</div>)}
      </div>
    </Ctx.Provider>
  );
}
