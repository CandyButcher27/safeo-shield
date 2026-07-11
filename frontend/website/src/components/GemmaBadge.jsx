import { createPortal } from "react-dom";

const BADGE_LABEL = "\u26A1 Powered by Gemma on AMD";

export function GemmaBadgeMarkup({ inline = false }) {
  return (
    <div
      className={`safeo-gemma-badge safeo-gemma-badge--default${
        inline ? " safeo-gemma-badge--inline" : ""
      }`}
      title="Gemma on AMD via Fireworks"
      role="status"
      aria-live="polite"
    >
      <span className="safeo-gemma-badge-dot" aria-hidden="true" />
      <span className="safeo-gemma-badge-text">{BADGE_LABEL}</span>
    </div>
  );
}

export default function GemmaBadge() {
  return createPortal(<GemmaBadgeMarkup />, document.body);
}
