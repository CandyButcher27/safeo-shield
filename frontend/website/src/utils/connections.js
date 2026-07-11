const STORAGE_KEY = "safeo_connections";
const SETTINGS_KEY = "safeo_settings";

const DEFAULT_CONNECTIONS = {
  odoo: {
    url: "http://127.0.0.1:8069",
    connected_at: null,
    status: "connected",
  },
};

export function getApiKey() {
  try {
    const s = JSON.parse(localStorage.getItem(SETTINGS_KEY) || "{}");
    return s.api_key || "internal";
  } catch {
    return "internal";
  }
}

export function loadConnections() {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return { ...DEFAULT_CONNECTIONS };
    return { ...DEFAULT_CONNECTIONS, ...JSON.parse(raw) };
  } catch {
    return { ...DEFAULT_CONNECTIONS };
  }
}

export function saveConnections(connections) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(connections));
}

export function seedOdooIfReachable(odooReachable) {
  const conns = loadConnections();
  if (odooReachable) {
    if (!conns.odoo?.connected_at) {
      conns.odoo = {
        url: "http://127.0.0.1:8069",
        connected_at: new Date().toISOString(),
        status: "connected",
      };
      saveConnections(conns);
    }
  }
  return conns;
}

export function markErpConnected(id, meta = {}) {
  const conns = loadConnections();
  conns[id] = {
    ...conns[id],
    ...meta,
    connected_at: new Date().toISOString(),
    status: "connected",
  };
  saveConnections(conns);
  return conns;
}

export function countReachableConnections(odooReachable, connections) {
  let n = 0;
  if (odooReachable) n += 1;
  for (const [key, val] of Object.entries(connections || {})) {
    if (key === "odoo") continue;
    if (val?.status === "connected") n += 1;
  }
  return n;
}
