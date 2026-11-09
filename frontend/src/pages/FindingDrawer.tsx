import { useState } from 'react';
import { api, ApiError } from '../lib/api';
import {
  Banner, Button, ConfirmDialog, ConfidenceTag, Drawer, EvidenceBlock, retestable, LoadError, Loading, LocationList, ReasonConfirm, SeverityBadge,
  StatusBadge, Textarea, Timeline, useToast,
} from '../components';
import { can, type AccessLevel } from '../lib/perm';
import { VOCAB } from '../lib/status';
import { useLoad } from '../lib/useLoad';
import type { FindingDetail, FindingState } from '../lib/types';

type StateAction = 'acknowledge' | 'under-review' | 'false-positive' | 'accept-risk' | 'reopen';
// DESIGN_SYSTEM §7.6
export const ACTIONS: { action: StateAction; label: string; from: FindingState[]; reason: boolean }[] = [
  { action: 'acknowledge', label: 'Acknowledge', from: ['new'], reason: false },
  { action: 'under-review', label: 'Mark under review', from: ['new', 'open', 'reopened'], reason: false },
  { action: 'false-positive', label: 'Mark false positive', from: ['new', 'open', 'under-review', 'reopened'], reason: true },
  { action: 'accept-risk', label: 'Accept risk', from: ['open', 'under-review', 'reopened'], reason: true },
  { action: 'reopen', label: 'Reopen', from: ['false-positive', 'accepted-risk', 'resolved'], reason: true },
];

export function FindingDrawer({ id, access, ownerName, moduleName, onClose, onChanged, onRetest, retestBlocked }: {
  onRetest?: (f: FindingDetail) => void; retestBlocked?: string; id: string; access: AccessLevel; ownerName: string; moduleName: (k: string) => string; onClose: () => void; onChanged: () => void;
}) {
  const { data, error, reload } = useLoad<FindingDetail>(`/findings/${id}`);
  const [pending, setPending] = useState<(typeof ACTIONS)[number] | null>(null);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<string | null>(null);
  const [comment, setComment] = useState('');
  const toast = useToast();
  const [f, setF] = useState<FindingDetail | null>(null);
  const d = f ?? data;

  const post = async (path: string, body: unknown, done: string) => {
    setBusy(true); setFailure(null);
    try {
      setF(await api<FindingDetail>(path, { method: 'POST', body }));
      toast(done);
      onChanged();
      return true;
    } catch (e) {
      setFailure(e instanceof ApiError ? e.detail : 'The change was not saved. Try again.');
      return false;
    } finally { setBusy(false); setPending(null); }
  };
  const change = (reason?: string) => post(`/findings/${id}/state`, { action: pending!.action, reason }, `${pending!.label}: saved.`);

  return (
    <Drawer
      open title={d?.title ?? `Finding ${id}`} onClose={onClose}
      badges={d && <><SeverityBadge severity={d.severity} /><ConfidenceTag confidence={d.confidence} /><StatusBadge kind="finding" status={d.state} /><span className="mono">{d.id}</span></>}
      footer={d && (can(access, 'change-finding-state')
        ? <>
          {ACTIONS.filter((a) => a.from.includes(d.state)).map((a) => <Button key={a.action} onClick={() => setPending(a)}>{a.label}</Button>)}
          {onRetest && retestable(d) && <Button variant="primary" disabled={!!retestBlocked} onClick={() => onRetest(d)}>Request retest</Button>}
          {onRetest && retestable(d) && retestBlocked && <small className="muted">{retestBlocked}</small>}
        </>
        : <span className="muted">{`Administrator view. Only the owner, ${ownerName}, can change this finding.`}</span>)}
    >
      {error && !d && <LoadError error={error} thing={`finding ${id}`} onRetry={reload} />}
      {!d && !error && <Loading />}
      {failure && <Banner tone="danger" title="Not saved">{failure}</Banner>}
      {d && (
        <>
          <section><h3>Where it is</h3>
            <LocationList location={d.location} module={moduleName(d.module)} foundBy={`${d.job_id} · policy ${d.policy_version}`} firstSeen={d.first_seen_at} lastSeen={d.last_seen_at} />
          </section>
          <section><h3>Description</h3><p className="prewrap">{d.description}</p></section>
          <section><h3>Impact</h3><p className="prewrap">{d.impact}</p></section>
          <section><h3>Evidence</h3><EvidenceBlock text={d.evidence} /></section>
          <section><h3>How to reproduce</h3><p className="prewrap">{d.reproduce}</p></section>
          <section><h3>Remediation</h3>
            <p className="prewrap">{d.remediation}</p>
            <span className="chips">
              {d.references.filter((r) => /^https?:\/\//i.test(r)).map((r) => <a key={r} className="chip" href={r} target="_blank" rel="noreferrer noopener">{r}</a>)}
            </span>
          </section>
          <section><h3>History</h3><Timeline rows={d.history.map((h) => ({ at: h.at, text: h.text }))} empty="No changes yet." /></section>
          <section><h3>Comments</h3>
            <Timeline rows={d.comments.map((c) => ({ at: c.at, text: <><b>{c.by}</b> {c.text}</> }))} empty="No comments yet." />
            {can(access, 'comment') && (
              <>
                <Textarea id="comment" label="Add a comment" value={comment} onChange={(e) => setComment(e.target.value)} />
                <Button disabled={!comment.trim()} busy={busy} onClick={async () => { if (await post(`/findings/${id}/comments`, { text: comment.trim() }, 'Comment added.')) setComment(''); }}>Post comment</Button>
              </>
            )}
          </section>
        </>
      )}
      {pending && (pending.reason
        ? <ReasonConfirm open title={`${pending.label}?`} cancelLabel="Cancel" confirmLabel={pending.label} busy={busy} onCancel={() => setPending(null)} onConfirm={change}>
            {pending.action === 'accept-risk' ? 'The finding stays unresolved in reports.' : 'Say why, so the history shows the reasoning.'}
          </ReasonConfirm>
        : <ConfirmDialog open title={`${pending.label}?`} cancelLabel="Cancel" confirmLabel={pending.label} busy={busy} onCancel={() => setPending(null)} onConfirm={() => change()}>
            {`This changes ${id} to ${VOCAB.finding[pending.action === 'acknowledge' ? 'open' : 'under-review'].label}.`}
          </ConfirmDialog>)}
    </Drawer>
  );
}
