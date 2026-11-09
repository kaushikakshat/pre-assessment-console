import type { ButtonHTMLAttributes } from 'react';
import { Icon, type IconName } from './Icon';

export type ButtonVariant = 'primary' | 'secondary' | 'quiet' | 'danger' | 'danger-outline';
interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: 'md' | 'sm';
  icon?: IconName;
  busy?: boolean;
  busyLabel?: string;
}

export function Button({ variant = 'secondary', size = 'md', icon, busy, busyLabel, children, className, disabled, ...rest }: ButtonProps) {
  return (
    <button
      type="button"
      {...rest}
      disabled={disabled || busy}
      aria-busy={busy || undefined}
      className={`btn btn-${variant} btn-${size} ${className ?? ''}`}
    >
      {(busy || icon) && <Icon name={busy ? 'spin' : icon!} size={size === 'sm' ? 14 : 16} />}
      {busy && busyLabel ? busyLabel : children}
    </button>
  );
}
