import type { ReactNode } from 'react';
import { Icon, type IconName } from './Icon';

type BannerTone = 'info' | 'warn' | 'danger' | 'ok';
const ICON: Record<BannerTone, IconName> = { info: 'info', warn: 'warn', danger: 'stop', ok: 'check' };

export function Banner({ tone, title, children, action }: { tone: BannerTone; title?: string; children: ReactNode; action?: ReactNode }) {
  return (
    <div className={`banner banner-${tone}`} role={tone === 'danger' ? 'alert' : 'note'}>
      <Icon name={ICON[tone]} />
      <div className="banner-body">
        {title && <strong className="banner-title">{title}</strong>}
        {children}
      </div>
      {action && <div className="banner-action">{action}</div>}
    </div>
  );
}

export function Disclaimer() {
  return (
    <Banner tone="warn" title="Pre-assessment, not a security clearance">
      These results help prepare for formal security testing. They are not a penetration test, statutory certificate or security clearance, and they are not exhaustive.
    </Banner>
  );
}
