import { useState } from 'react';
import { api, ApiError } from '../lib/api';
import type { Assessment } from '../lib/types';
import { Banner } from './Banner';
import { Button } from './Button';
import { Textarea } from './Fields';
import { Modal } from './Overlay';
import { ValidationResult } from './Scan';

/** Admin decision on an approval-required target (§7.15). `own` adds the self-approval warning. Mounted only while open. */
export function ApprovalDecision({ assessment, own, onClose, onDecided }: {
  assessment: Assessment; own: boolean; onClose: () => void; onDecided: (decision: 'approve' | 'refuse') => void;
}) {
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState<'approve' | 'refuse' | null>(null);
  const [failure, setFailure] = useState<string | null>(null);
  const decide = async (decision: 'approve' | 'refuse') => {
    setBusy(decision); setFailure(null);
    try {
      await api(`/admin/approvals/${assessment.id}`, { method: 'POST', body: { decision, note: note.trim() } });
      onDecided(decision);
    } catch (e) {
      setFailure(e instanceof ApiError ? e.detail : 'The decision was not saved. Try again.');
      setBusy(null);
    }
  };
  const off = note.trim() === '' || busy !== null;
  return (
    <Modal open wide title={own ? 'Approve my target' : `Decide on ${assessment.name}`} onClose={onClose}
      footer={<>
        <Button onClick={onClose}>Cancel</Button>
        <Button variant="danger-outline" disabled={off} busy={busy === 'refuse'} onClick={() => decide('refuse')}>Refuse</Button>
        <Button variant="primary" disabled={off} busy={busy === 'approve'} onClick={() => decide('approve')}>Approve</Button>
      </>}>
      {own && <Banner tone="warn" title="Self-approval">This is your own target. Self-approval is allowed with a reason, and it is flagged in the audit log.</Banner>}
      {assessment.validation && <ValidationResult validation={assessment.validation} />}
      <Textarea id="approval-note" label="Note" required hint="Shown to the owner and recorded in the audit log." value={note} onChange={(e) => setNote(e.target.value)} />
      {failure && <Banner tone="danger" title="Not saved">{failure}</Banner>}
    </Modal>
  );
}
