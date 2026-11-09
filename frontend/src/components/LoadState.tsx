import type { ApiError } from '../lib/api';
import { Banner } from './Banner';
import { DeniedState } from './Card';

/** Spinner-less placeholder so a loading screen is never blank. */
export function Loading({ what = 'Loading…' }: { what?: string }) {
  return <p className="boot muted" role="status">{what}</p>;
}

/** 404/403 on an object -> DeniedState (no existence oracle); anything else -> danger banner with a next step. */
export function LoadError({ error, thing, onRetry }: { error: ApiError; thing: string; onRetry?: () => void }) {
  if (error.status === 404 || error.status === 403) {
    return <DeniedState thing={thing} reason="It may not exist, or it belongs to someone else. Check the link, or return to your dashboard." />;
  }
  return (
    <Banner tone="danger" title="This page could not be loaded" action={onRetry && <button type="button" className="btn btn-secondary btn-sm" onClick={onRetry}>Try again</button>}>
      {error.detail} Try again, or come back in a few minutes.
    </Banner>
  );
}
