import { useState } from 'react';
import { render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import { Button, EvidenceBlock, ReasonConfirm, ValidationResult, DataTable } from '../components';
import type { Validation } from '../lib/types';

function Harness({ onConfirm }: { onConfirm: (r: string) => void }) {
  const [open, setOpen] = useState(false);
  return (
    <>
      <Button onClick={() => setOpen(true)}>Open</Button>
      <ReasonConfirm open={open} title="Stop?" cancelLabel="Keep going" confirmLabel="Stop" tone="danger" typedConfirmation="STOP"
        onCancel={() => setOpen(false)} onConfirm={onConfirm}>Consequence.</ReasonConfirm>
    </>
  );
}

it('ReasonConfirm: focus moves in, confirm needs reason + typed text, Esc closes and returns focus', async () => {
  const user = userEvent.setup();
  const onConfirm = vi.fn();
  render(<Harness onConfirm={onConfirm} />);
  const trigger = screen.getByRole('button', { name: 'Open' });
  await user.click(trigger);
  const dialog = screen.getByRole('alertdialog', { name: 'Stop?' });
  expect(dialog.contains(document.activeElement)).toBe(true);
  const confirm = screen.getByRole('button', { name: 'Stop' }) as HTMLButtonElement;
  expect(confirm.disabled).toBe(true);
  await user.type(screen.getByLabelText(/Reason/), 'Because');
  expect(confirm.disabled).toBe(true);
  await user.type(screen.getByLabelText(/Type STOP/), 'STOP');
  expect(confirm.disabled).toBe(false);
  await user.click(confirm);
  expect(onConfirm).toHaveBeenCalledWith('Because');
  await user.keyboard('{Escape}');
  expect(screen.queryByRole('alertdialog')).toBeNull();
  expect(document.activeElement).toBe(trigger);
});

it('ValidationResult keeps the fixed order and marks checks after a failure as skipped', () => {
  const v: Validation = {
    outcome: 'blocked', normalized_target: 'https://x.example/', policy_version: 'v1', decided_at: '2026-11-02T08:50:00Z',
    checks: [
      { key: 'dns', label: 'DNS resolution', result: 'fail', detail: 'Resolves to a loopback address.' },
      { key: 'url', label: 'URL normalised', result: 'pass', detail: 'ok' },
      { key: 'addresses', label: 'Destination addresses', result: 'pass', detail: 'would be wrongly green' },
    ],
  };
  render(<ValidationResult validation={v} />);
  const items = screen.getAllByRole('listitem').map((li) => li.textContent);
  expect(items[0]).toContain('URL normalised');
  expect(items[1]).toContain('DNS resolution');
  expect(items[2]).toContain('Not evaluated after a blocking result');
  expect(screen.getByText('Blocked — no scan traffic will be sent')).toBeTruthy();
  expect(screen.getByText(/02 Nov 2026, 14:20 IST/)).toBeTruthy();
});

it('EvidenceBlock highlights [REDACTED]; DataTable shows an empty state, not an empty grid', () => {
  const { container } = render(<MemoryRouter><EvidenceBlock text="Set-Cookie: sid=[REDACTED]" /><DataTable columns={[]} rows={[]} rowKey={() => ''} empty={{ title: 'Nothing yet' }} /></MemoryRouter>);
  expect(container.querySelector('mark')?.textContent).toBe('[REDACTED]');
  expect(screen.getByText('Nothing yet')).toBeTruthy();
  expect(container.querySelector('table')).toBeNull();
});
