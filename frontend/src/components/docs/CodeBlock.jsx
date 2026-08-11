export function CodeBlock({ children }) {
  return (
    <pre
      className="overflow-x-auto rounded-lg border p-4 font-mono leading-relaxed"
      style={{
        fontSize:        '12px',
        backgroundColor: 'var(--color-bg-page)',
        borderColor:     'var(--color-border-card)',
        color:           '#10b981'
      }}
    >
      {children}
    </pre>
  )
}
