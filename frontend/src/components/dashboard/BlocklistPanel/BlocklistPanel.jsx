import { memo } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { Ban, ShieldOff } from 'lucide-react'
import { BlocklistItem } from './BlocklistItem'
import { Card } from '../../ui/Card'

function BlocklistPanelInner({ blocklist, onUnblockIP, isAuthenticated }) {
  return (
    <Card className="overflow-hidden flex flex-col h-full">
      <div
        className="flex items-center justify-between border-b px-4 py-3 sm:px-5"
        style={{ borderColor: 'var(--color-border-card)' }}
      >
        <div className="flex items-center gap-2">
          <Ban size={14} strokeWidth={1.75} style={{ color: 'var(--color-text-muted)' }} aria-hidden="true" />
          <h2 className="text-sm font-semibold" style={{ color: 'var(--color-text-primary)' }}>
            Blocklist
          </h2>
          <motion.span
            key={blocklist.length}
            initial={{ scale: 1.3, opacity: 0.6 }}
            animate={{ scale: 1,   opacity: 1   }}
            transition={{ duration: 0.25 }}
            className="rounded-full px-2 py-0.5 text-xs font-medium"
            style={{
              backgroundColor: 'rgba(245,158,11,0.12)',
              border:          '1px solid rgba(245,158,11,0.25)',
              color:           '#f59e0b'
            }}
          >
            {blocklist.length}
          </motion.span>
        </div>

        <div className="flex items-center gap-2">
          <span
            className="rounded-full px-2 py-0.5"
            style={{
              fontSize:        '10px',
              backgroundColor: 'rgba(100,116,139,0.1)',
              border:          '1px solid rgba(100,116,139,0.2)',
              color:           'var(--color-text-muted)'
            }}
          >
            Expires in 30 min
          </span>
        </div>
      </div>

      {blocklist.length === 0 ? (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          className="flex flex-col items-center gap-3 px-4 py-10 sm:px-5"
        >
          <ShieldOff size={28} strokeWidth={1.25} style={{ color: 'var(--color-text-muted)', opacity: 0.4 }} aria-hidden="true" />
          <div className="text-center">
            <p className="text-sm font-medium" style={{ color: 'var(--color-text-secondary)' }}>No blocked IPs</p>
            <p className="mt-1" style={{ fontSize: '12px', color: 'var(--color-text-muted)' }}>Block IPs from the threat table</p>
          </div>
        </motion.div>
      ) : (
        <motion.div layout className="flex-1 overflow-y-auto">
          <AnimatePresence initial={false}>
            {blocklist.map((entry) => (
              <motion.div
                key={entry.ip || entry._id}
                layout
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: 'auto' }}
                exit={{    opacity: 0, x: 28, height: 0 }}
                transition={{
                  opacity: { duration: 0.2 },
                  height:  { duration: 0.22, ease: 'easeOut' },
                  x:       { duration: 0.18 }
                }}
                style={{ overflow: 'hidden' }}
              >
                <BlocklistItem
                  entry={entry}
                  onUnblock={onUnblockIP}
                  isAuthenticated={isAuthenticated}
                />
              </motion.div>
            ))}
          </AnimatePresence>
        </motion.div>
      )}
    </Card>
  )
}

export const BlocklistPanel = memo(BlocklistPanelInner)