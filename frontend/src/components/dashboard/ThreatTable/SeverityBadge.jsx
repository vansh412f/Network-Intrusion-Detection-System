import { memo } from 'react'
import { Badge } from '../../ui/Badge'

const SEVERITY_VARIANT = {
  LOW:      { variant: 'low',      pulse: false },
  MEDIUM:   { variant: 'medium',   pulse: false },
  HIGH:     { variant: 'high',     pulse: false },
  CRITICAL: { variant: 'critical', pulse: true  }
}

function SeverityBadgeInner({ severity }) {
  const config = SEVERITY_VARIANT[severity] || SEVERITY_VARIANT.LOW

  return (
    <Badge
      variant={config.variant}
      pulse={config.pulse}
      size="xs"
      ariaLabel={`Severity: ${severity}`}
    >
      {severity || 'LOW'}
    </Badge>
  )
}

export const SeverityBadge = memo(SeverityBadgeInner)