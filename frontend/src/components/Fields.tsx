import type { InputHTMLAttributes, ReactNode, SelectHTMLAttributes, TextareaHTMLAttributes } from 'react';
import { Icon } from './Icon';

interface FieldProps { id: string; label: string; required?: boolean; hint?: string; error?: string; mono?: boolean }

function Field({ id, label, required, hint, error, children }: FieldProps & { children: ReactNode }) {
  return (
    <div className="field">
      <label htmlFor={id}>
        {label}
        {required && <span className="req" aria-hidden="true"> *</span>}
      </label>
      {children}
      {error ? (
        <p id={`${id}-msg`} className="field-error"><Icon name="x" size={14} />{error}</p>
      ) : hint ? (
        <p id={`${id}-msg`} className="field-hint">{hint}</p>
      ) : null}
    </div>
  );
}

const wire = ({ id, required, hint, error, mono }: FieldProps) => ({
  id,
  required,
  'aria-invalid': error ? true : undefined,
  'aria-describedby': error || hint ? `${id}-msg` : undefined,
  className: `control${mono ? ' mono' : ''}`,
});

export function TextField(p: FieldProps & Omit<InputHTMLAttributes<HTMLInputElement>, keyof FieldProps>) {
  const { label, hint, error, mono, ...rest } = p;
  return <Field {...p}><input {...rest} {...wire(p)} /></Field>;
}

export function Select(p: FieldProps & Omit<SelectHTMLAttributes<HTMLSelectElement>, keyof FieldProps>) {
  const { label, hint, error, mono, children, ...rest } = p;
  return <Field {...p}><select {...rest} {...wire(p)}>{children}</select></Field>;
}

export function Textarea(p: FieldProps & Omit<TextareaHTMLAttributes<HTMLTextAreaElement>, keyof FieldProps>) {
  const { label, hint, error, mono, ...rest } = p;
  return <Field {...p}><textarea rows={3} {...rest} {...wire(p)} /></Field>;
}

type InputProps = Omit<InputHTMLAttributes<HTMLInputElement>, 'type'> & { label: ReactNode };

export function Checkbox({ label, ...rest }: InputProps) {
  return <label className="check"><input type="checkbox" {...rest} />{label}</label>;
}

export function Radio({ label, ...rest }: InputProps) {
  return <label className="check"><input type="radio" {...rest} />{label}</label>;
}

/** Bordered label wrapping a checkbox/radio + title + description. `checked` drives the selected style. */
export function OptionCard({ type = 'checkbox', title, description, ...rest }: Omit<InputHTMLAttributes<HTMLInputElement>, 'type' | 'title'> & { type?: 'checkbox' | 'radio'; title: string; description?: string }) {
  return (
    <label className={`optcard${rest.checked ? ' selected' : ''}${rest.disabled ? ' disabled' : ''}`}>
      <input type={type} {...rest} />
      <span>
        <strong>{title}</strong>
        {description && <small>{description}</small>}
      </span>
    </label>
  );
}
