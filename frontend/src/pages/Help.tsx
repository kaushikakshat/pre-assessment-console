import { Card, Disclaimer } from '../components';

export function Help() {
  return (
    <div className="stack-lg">
      <h1>Help & Safety Guidance</h1>
      <Disclaimer />
      <Card title="Scan profiles">
        <ul className="plain">
          <li><b>Quick Scan</b> — checks that the target is reachable, then looks at open ports, TLS settings, security headers, exposed files and the technology it reveals. Seconds to minutes for small targets. Low impact. Available in this release.</li>
          <li><b>Pre-Assessment</b> — a wider set of checks. Minutes to tens of minutes. Moderate impact. Not available in this release.</li>
          <li><b>Deep Scan</b> — the widest set of checks. Tens of minutes to hours, and still not exhaustive. Higher impact. Not available in this release.</li>
        </ul>
      </Card>
      <Card title="Before any scan runs">
        <p>Every target is validated first. No scan traffic is sent unless validation returns Allowed, or an administrator approves a target that needs approval. You confirm you are authorized to test the target each time you submit a scan.</p>
      </Card>
      <Card title="What is always blocked, and why">
        <ul className="plain">
          <li>Loopback, unspecified and link-local addresses, so a scan can never reach the scanner itself or its local network.</li>
          <li>Cloud metadata addresses, which can expose credentials for the hosting account.</li>
          <li>Private address ranges, unless an approved internal policy allows them.</li>
          <li>Redirects or DNS answers that lead outside the scope you declared, so a scan never wanders onto systems you did not name.</li>
        </ul>
        <p>Scans are bounded and non-destructive. If a scan is interrupted, partial results are kept and unfinished modules are reported as not tested.</p>
      </Card>
      <Card title="Reading results">
        <p>Severity and confidence are separate: severity is how serious a finding would be, confidence is how sure the scanner is. Evidence is always redacted; cookies, tokens and personal data show as [REDACTED].</p>
      </Card>
    </div>
  );
}
