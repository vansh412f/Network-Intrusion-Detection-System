export const SECTIONS = [
  { id: 'overview',     label: 'Overview',        icon: 'BookOpen' },
  { id: 'architecture', label: 'Architecture',    icon: 'Layers'   },
  { id: 'sensor-modes', label: 'Sensor Modes',    icon: 'Terminal' },
  { id: 'integration',  label: 'Integration',     icon: 'Globe'    },
  { id: 'demo',         label: 'Live Demo',       icon: 'Globe'    },
  { id: 'ml',           label: 'ML Model',        icon: 'Brain'    },
  { id: 'api',          label: 'API Reference',   icon: 'Terminal' },
  { id: 'websockets',   label: 'Socket.io',       icon: 'Zap'      },
  { id: 'auth',         label: 'Authentication',  icon: 'Layers'   },
  { id: 'blocklist',    label: 'Blocklist',       icon: 'Shield'   },
  { id: 'email',        label: 'Email Alerts',    icon: 'Mail'     },
  { id: 'manual',       label: 'Manual Predict',  icon: 'Terminal' },
  { id: 'running',      label: 'Running Locally', icon: 'Terminal' }
]

export const API_ROUTES = [
  { method: 'POST',  route: '/api/auth/register',     auth: 'None',   desc: 'Create new analyst account' },
  { method: 'POST',  route: '/api/auth/login',        auth: 'None',   desc: 'Login and set httpOnly JWT cookie' },
  { method: 'POST',  route: '/api/auth/logout',       auth: 'None',   desc: 'Clear session cookie' },
  { method: 'GET',   route: '/api/auth/verify',       auth: 'None',   desc: 'Verify email via token link' },
  { method: 'GET',   route: '/api/auth/unsubscribe',  auth: 'None',   desc: 'Opt-out of emails via token' },
  { method: 'GET',   route: '/api/auth/me',           auth: 'JWT',    desc: 'Get authenticated user profile' },
  { method: 'PATCH', route: '/api/auth/me',           auth: 'JWT',    desc: 'Update email preferences' },
  { method: 'GET',   route: '/api/alerts',            auth: 'None',   desc: 'Fetch last 500 threat alerts' },
  { method: 'POST',  route: '/api/predict/manual',    auth: 'JWT',    desc: 'Run ML predict via Python subprocess' },
  { method: 'GET',   route: '/api/blocklist',         auth: 'None',   desc: 'View active IP blocklist' },
  { method: 'POST',  route: '/api/blocklist/block',   auth: 'JWT',    desc: 'Block source IP (3 per 30m limit)' },
  { method: 'POST',  route: '/api/blocklist/unblock', auth: 'JWT',    desc: 'Remove IP from blocklist' },
  { method: 'GET',   route: '/api/blocklist/ips',     auth: 'Secret', desc: 'Sensor polls active blocks' },
  { method: 'POST',  route: '/api/internal/alert',    auth: 'Secret', desc: 'Sensor posts detected threat' },
  { method: 'POST',  route: '/api/internal/stats',    auth: 'Secret', desc: 'Sensor posts traffic stats' },
  { method: 'GET',   route: '/health',                auth: 'None',   desc: 'Server health check' }
]

export const WS_EVENTS = [
  { event: 'ThreatDetected', payload: '{ _id, source_ip, probability, threat_type, severity, createdAt }', desc: 'Sensor detected a threat' },
  { event: 'LiveStats',      payload: '{ window_number, total_packets, total_flows, timestamp, mode }',     desc: 'Sensor traffic stats (every 2s)' },
  { event: 'IPBlocked',      payload: '{ ip, blockedBy, createdAt }',                                       desc: 'Analyst blocked an IP' },
  { event: 'IPUnblocked',    payload: '{ ip }',                                                             desc: 'Analyst unblocked an IP' }
]

export const ML_FEATURES = [
  { name: 'Flow Duration',            desc: 'Total duration of the network flow' },
  { name: 'Flow IAT Mean',            desc: 'Mean inter-arrival time between packets' },
  { name: 'Flow IAT Max',             desc: 'Maximum inter-arrival time' },
  { name: 'Flow IAT Std',             desc: 'Standard deviation of inter-arrival times' },
  { name: 'Fwd Packets/s',            desc: 'Forward packets per second' },
  { name: 'Bwd Packets/s',            desc: 'Backward packets per second' },
  { name: 'Flow Packets/s',           desc: 'Total flow packets per second' },
  { name: 'Flow Bytes/s',             desc: 'Total flow bytes per second' },
  { name: 'Fwd Packet Length Max',    desc: 'Maximum forward packet length' },
  { name: 'Fwd Packet Length Min',    desc: 'Minimum forward packet length' },
  { name: 'Fwd Packets Length Total', desc: 'Total bytes in forward direction' },
  { name: 'Packet Length Max',        desc: 'Maximum packet length in flow' },
  { name: 'Fwd Act Data Packets',     desc: 'Forward packets with actual payload' },
  { name: 'Total Backward Packets',   desc: 'Total packets in backward direction' },
  { name: 'ACK Flag Count',           desc: 'Whether ACK flag was set in flow' }
]
