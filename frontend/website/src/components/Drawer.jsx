export default function Drawer({ open, title, onClose, children }) {
  if (!open) return null;
  return (
    <div className="safeo-drawer-overlay" onClick={onClose}>
      <div className="safeo-drawer" onClick={(e) => e.stopPropagation()}>
        <div className="safeo-drawer-header">
          <h3>{title}</h3>
          <button type="button" className="safeo-drawer-close" onClick={onClose} aria-label="Close">
            ×
          </button>
        </div>
        <div className="safeo-drawer-body">{children}</div>
      </div>
    </div>
  );
}
