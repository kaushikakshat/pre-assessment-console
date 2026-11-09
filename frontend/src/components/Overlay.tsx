// Modal, ConfirmDialog, ReasonConfirm, Drawer. Shared behaviour: focus moves in on open, Esc + scrim close,
// Tab stays inside, focus returns to the trigger.
import { useEffect, useId, useRef, useState, type ReactNode } from 'react';
import { createPortal } from 'react-dom';
import { Button } from './Button';
import { Icon } from './Icon';
import { Textarea, TextField } from './Fields';

const FOCUSABLE = 'a[href],button:not([disabled]),input:not([disabled]),select:not([disabled]),textarea:not([disabled]),[tabindex]:not([tabindex="-1"])';

function useOverlay(onClose: () => void) {
  const ref = useRef<HTMLDivElement>(null);
  const close = useRef(onClose);
  close.current = onClose;
  useEffect(() => {
    const trigger = document.activeElement as HTMLElement | null;
    const el = ref.current!;
    (el.querySelector<HTMLElement>(FOCUSABLE) ?? el).focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { e.stopPropagation(); close.current(); }
      if (e.key !== 'Tab') return;
      const items = [...el.querySelectorAll<HTMLElement>(FOCUSABLE)];
      if (!items.length) return;
      const [first, last] = [items[0], items[items.length - 1]];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    };
    document.addEventListener('keydown', onKey);
    return () => { document.removeEventListener('keydown', onKey); trigger?.focus?.(); };
  }, []);
  return ref;
}

interface ModalProps { open: boolean; title: string; onClose: () => void; wide?: boolean; alert?: boolean; footer?: ReactNode; children: ReactNode }

export function Modal(props: ModalProps) {
  return props.open ? createPortal(<ModalInner {...props} />, document.body) : null;
}

function ModalInner({ title, onClose, wide, alert, footer, children }: ModalProps) {
  const ref = useOverlay(onClose);
  const titleId = useId();
  return (
    <>
      <div className="scrim modal-scrim" onClick={onClose} />
      <div ref={ref} tabIndex={-1} role={alert ? 'alertdialog' : 'dialog'} aria-modal="true" aria-labelledby={titleId} className={`modal${wide ? ' wide' : ''}`}>
        <div className="modal-body">
          <h2 id={titleId} className="dialog-title">{title}</h2>
          {children}
        </div>
        {footer && <footer className="modal-foot">{footer}</footer>}
      </div>
    </>
  );
}

const AUDIT_LINE = (
  <span className="audit-line"><Icon name="doc" size={14} />This action is recorded in the audit log.</span>
);

interface ConfirmProps {
  open: boolean; title: string; children: ReactNode; cancelLabel: string; confirmLabel: string;
  tone?: 'danger' | 'primary'; busy?: boolean; onCancel: () => void; onConfirm: () => void;
}

export function ConfirmDialog({ open, title, children, cancelLabel, confirmLabel, tone = 'primary', busy, onCancel, onConfirm }: ConfirmProps) {
  return (
    <Modal
      open={open} alert title={title} onClose={onCancel}
      footer={<>{AUDIT_LINE}<Button onClick={onCancel}>{cancelLabel}</Button><Button variant={tone} busy={busy} onClick={onConfirm}>{confirmLabel}</Button></>}
    >
      <p>{children}</p>
    </Modal>
  );
}

interface ReasonProps extends Omit<ConfirmProps, 'onConfirm'> {
  typedConfirmation?: string; // e.g. "STOP"
  onConfirm: (reason: string) => void;
  extra?: ReactNode;
}

export function ReasonConfirm(p: ReasonProps) {
  return p.open ? <ReasonForm {...p} /> : null; // mounted only while open so the reason resets
}

function ReasonForm({ typedConfirmation, onConfirm, extra, ...p }: ReasonProps) {
  const [reason, setReason] = useState('');
  const [typed, setTyped] = useState('');
  const ok = reason.trim() !== '' && (!typedConfirmation || typed === typedConfirmation);
  return (
    <Modal
      open alert title={p.title} onClose={p.onCancel}
      footer={<>{AUDIT_LINE}<Button onClick={p.onCancel}>{p.cancelLabel}</Button>
        <Button variant={p.tone ?? 'primary'} busy={p.busy} disabled={!ok} onClick={() => onConfirm(reason.trim())}>{p.confirmLabel}</Button></>}
    >
      <p>{p.children}</p>
      {extra}
      <Textarea id="reason" label="Reason" required hint="Recorded in the audit log." value={reason} onChange={(e) => setReason(e.target.value)} />
      {typedConfirmation && (
        <TextField id="typed" label={`Type ${typedConfirmation} to confirm`} required mono autoComplete="off" value={typed} onChange={(e) => setTyped(e.target.value)} />
      )}
    </Modal>
  );
}

interface DrawerProps { open: boolean; title: string; badges?: ReactNode; onClose: () => void; footer?: ReactNode; children: ReactNode }

export function Drawer(props: DrawerProps) {
  return props.open ? createPortal(<DrawerInner {...props} />, document.body) : null;
}

function DrawerInner({ title, badges, onClose, footer, children }: DrawerProps) {
  const ref = useOverlay(onClose);
  const titleId = useId();
  return (
    <>
      <div className="scrim drawer-scrim" onClick={onClose} />
      <aside ref={ref} tabIndex={-1} role="dialog" aria-modal="true" aria-labelledby={titleId} className="drawer">
        <header className="drawer-head">
          <div>
            {badges && <div className="badge-row">{badges}</div>}
            <h2 id={titleId} className="dialog-title">{title}</h2>
          </div>
          <button type="button" className="icon-btn" aria-label="Close" onClick={onClose}><Icon name="close" /></button>
        </header>
        <div className="drawer-body">{children}</div>
        {footer && <footer className="drawer-foot">{footer}</footer>}
      </aside>
    </>
  );
}
