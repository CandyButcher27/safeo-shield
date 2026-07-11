export default function Modal({ open, title, onClose, children }) {
  if (!open) return null;
  return (
    <div className="safeo-modal-overlay" onClick={onClose}>
      <div className="safeo-modal" onClick={(e) => e.stopPropagation()}>
        <div className="safeo-modal-header">
          <h3>{title}</h3>
          <button type="button" className="safeo-drawer-close" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>
        <div className="safeo-modal-body">{children}</div>
      </div>
    </div>
  );
}
