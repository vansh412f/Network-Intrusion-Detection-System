import { Clock, Activity, Hash, Zap } from 'lucide-react'

// ── FEATURE DEFINITIONS ──────────────────────────────────────────────────────

export const FEATURE_GROUPS = [
  {
    label: 'Timing',
    icon:  Clock,
    fields: [
      { key: 'Flow Duration',  min: 0, max: 120000000, step: 1000, placeholder: 'μs' },
      { key: 'Flow IAT Mean', min: 0, max: 10000000,  step: 1,    placeholder: 'μs' },
      { key: 'Flow IAT Max',  min: 0, max: 50000000,  step: 1,    placeholder: 'μs' },
      { key: 'Flow IAT Std',  min: 0, max: 10000000,  step: 0.1,  placeholder: ''   }
    ]
  },
  {
    label: 'Packet Rate',
    icon:  Activity,
    fields: [
      { key: 'Fwd Packets/s',  min: 0, max: 1000000,   step: 1, placeholder: 'pkt/s' },
      { key: 'Bwd Packets/s',  min: 0, max: 1000000,   step: 1, placeholder: 'pkt/s' },
      { key: 'Flow Packets/s', min: 0, max: 2000000,   step: 1, placeholder: 'pkt/s' },
      { key: 'Flow Bytes/s',   min: 0, max: 100000000, step: 1, placeholder: 'B/s'   }
    ]
  },
  {
    label: 'Packet Size',
    icon:  Hash,
    fields: [
      { key: 'Fwd Packet Length Max',    min: 0, max: 65535,     step: 1, placeholder: 'bytes' },
      { key: 'Fwd Packet Length Min',    min: 0, max: 65535,     step: 1, placeholder: 'bytes' },
      { key: 'Fwd Packets Length Total', min: 0, max: 100000000, step: 1, placeholder: 'bytes' },
      { key: 'Packet Length Max',        min: 0, max: 65535,     step: 1, placeholder: 'bytes' }
    ]
  },
  {
    label: 'Counts',
    icon:  Zap,
    fields: [
      { key: 'Fwd Act Data Packets',   min: 0, max: 32767, step: 1, placeholder: '' },
      { key: 'Total Backward Packets', min: 0, max: 32767, step: 1, placeholder: '' }
    ]
  }
]

export const ALL_FIELDS = FEATURE_GROUPS.flatMap(g => g.fields)

// ── CALIBRATED TEMPLATES ─────────────────────────────────────────────────────
// All values validated against live XGBoost model via find_critical.py
// Normal:   0.04%  (target <20%)
// Low:     82.39%  (target 81-84%)
// Medium:  89.21%  (target 88-91%)
// High:    94.96%  (target 94-96%)
// Critical: 99.99% (target 98-99%)

export const TEMPLATES = {
  NORMAL: {
    label:  'Normal',
    color:  '#10b981',
    bg:     'rgba(16,185,129,0.08)',
    border: 'rgba(16,185,129,0.2)',
    // Strategy: very low rate + long IAT + large packets → clearly benign
    // pkt_len_min=300 → 10.58%, pkt_len_max=1500 → 14.86% from sweep
    // Combined with short duration → 0.04%
    features: {
      'Flow Duration':            150000,
      'Flow IAT Mean':            5000,
      'Flow IAT Max':             50000,
      'Flow IAT Std':             2000,
      'Fwd Packets/s':            100,
      'Bwd Packets/s':            100,
      'Flow Packets/s':           200,
      'Flow Bytes/s':             150000,
      'Fwd Packet Length Max':    1400,
      'Fwd Packet Length Min':    300,
      'Fwd Packets Length Total': 0,
      'Packet Length Max':        1500,
      'Fwd Act Data Packets':     0,
      'Total Backward Packets':   10,
      'ACK Flag Count':           '0',
    }
  },

  LOW: {
    label:  'Low',
    color:  '#64748b',
    bg:     'rgba(100,116,139,0.08)',
    border: 'rgba(100,116,139,0.2)',
    // Strategy: rate=9000 → 82.39% confirmed from sweep
    // ACK=0, all packet length fields zeroed, standard IAT
    features: {
      'Flow Duration':            1000000,
      'Flow IAT Mean':            20,
      'Flow IAT Max':             200,
      'Flow IAT Std':             10,
      'Fwd Packets/s':            9000,
      'Bwd Packets/s':            9000,
      'Flow Packets/s':           18000,
      'Flow Bytes/s':             27000,
      'Fwd Packet Length Max':    0,
      'Fwd Packet Length Min':    0,
      'Fwd Packets Length Total': 0,
      'Packet Length Max':        0,
      'Fwd Act Data Packets':     0,
      'Total Backward Packets':   9000,
      'ACK Flag Count':           '0',
    }
  },

  MEDIUM: {
    label:  'Medium',
    color:  '#f59e0b',
    bg:     'rgba(245,158,11,0.08)',
    border: 'rgba(245,158,11,0.2)',
    // Strategy: Medium-A from validation → 89.21% ✓
    // IAT=200 baseline + pkt_len_max=20 pulls from 95.93% down to 89.21%
    // ACK=0, fwd_pkt_len fields zeroed
    features: {
      'Flow Duration':            1000000,
      'Flow IAT Mean':            200,
      'Flow IAT Max':             2000,
      'Flow IAT Std':             60,
      'Fwd Packets/s':            8000,
      'Bwd Packets/s':            8000,
      'Flow Packets/s':           16000,
      'Flow Bytes/s':             30000,
      'Fwd Packet Length Max':    0,
      'Fwd Packet Length Min':    0,
      'Fwd Packets Length Total': 0,
      'Packet Length Max':        20,
      'Fwd Act Data Packets':     0,
      'Total Backward Packets':   8000,
      'ACK Flag Count':           '0',
    }
  },

  HIGH: {
    label:  'High',
    color:  '#fb923c',
    bg:     'rgba(251,146,60,0.08)',
    border: 'rgba(251,146,60,0.2)',
    // Strategy: pkt_len_max=500 → 94.96% confirmed from sweep
    // ACK=0 to avoid ACK=1 super-additive interaction pushing to 99%+
    // All other packet length fields zeroed, IAT=200 baseline
    features: {
      'Flow Duration':            1000000,
      'Flow IAT Mean':            200,
      'Flow IAT Max':             2000,
      'Flow IAT Std':             60,
      'Fwd Packets/s':            8000,
      'Bwd Packets/s':            8000,
      'Flow Packets/s':           16000,
      'Flow Bytes/s':             30000,
      'Fwd Packet Length Max':    0,
      'Fwd Packet Length Min':    0,
      'Fwd Packets Length Total': 0,
      'Packet Length Max':        500,
      'Fwd Act Data Packets':     0,
      'Total Backward Packets':   8000,
      'ACK Flag Count':           '0',
    }
  },

  CRITICAL: {
    label:  'Critical',
    color:  '#ef4444',
    bg:     'rgba(239,68,68,0.08)',
    border: 'rgba(239,68,68,0.2)',
    // Strategy: brute force winner → 99.99% confirmed
    // ACK=1 + fwd_pkt_len_min=40 + fwd_pkt_len_total=100000 + iat_std=0
    // Super-additive interaction of ACK flag + packet length minimum
    features: {
      'Flow Duration':            1000000,
      'Flow IAT Mean':            200,
      'Flow IAT Max':             500,
      'Flow IAT Std':             0,
      'Fwd Packets/s':            8000,
      'Bwd Packets/s':            8000,
      'Flow Packets/s':           16000,
      'Flow Bytes/s':             30000,
      'Fwd Packet Length Max':    0,
      'Fwd Packet Length Min':    40,
      'Fwd Packets Length Total': 100000,
      'Packet Length Max':        0,
      'Fwd Act Data Packets':     0,
      'Total Backward Packets':   8000,
      'ACK Flag Count':           '1',
    }
  }
}
