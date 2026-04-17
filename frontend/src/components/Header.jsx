// ============================================================
// src/components/Header.jsx
// Top navigation bar — connection status + Manual Input button
// ============================================================

export function Header({ isConnected, onOpenManualInput, onOpenDemo }) {
  return (
    <header className="bg-slate-800 border-b border-slate-700 px-6 py-4">
      <div className="max-w-7xl mx-auto flex items-center justify-between">

        {/* Left — Title */}
        <div className="flex items-center gap-3">
          <div className="text-2xl">🛡️</div>
          <div>
            <h1 className="text-xl font-bold text-white">
              NIDS SOC Dashboard
            </h1>
            <p className="text-xs text-slate-400">
              Real-Time Network Intrusion Detection
            </p>
          </div>
        </div>

        {/* Right — Status + Manual Input */}
        <div className="flex items-center gap-4">

          {/* Connection Status */}
          <div className="flex items-center gap-2">
            <div className="relative flex items-center justify-center">
              {isConnected && (
                <div className="absolute w-3 h-3 bg-green-400 rounded-full animate-ping opacity-75" />
              )}
              <div className={`w-3 h-3 rounded-full ${
                isConnected ? 'bg-green-400' : 'bg-red-500'
              }`} />
            </div>
            <span className={`text-sm font-medium ${
              isConnected ? 'text-green-400' : 'text-red-400'
            }`}>
              {isConnected ? 'Live' : 'Disconnected'}
            </span>
          </div>

          {/* Demo Video Button */}
          <button
            id="demo-video-btn"
            onClick={onOpenDemo}
            className="flex items-center gap-2 bg-slate-700 hover:bg-slate-600
                       text-white font-medium py-2 px-4 rounded-lg
                       text-sm transition-colors border border-slate-600"
          >
            🎬 Demo
          </button>

          {/* Manual Input Button */}
          <button
            id="manual-input-btn"
            onClick={onOpenManualInput}
            className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700
                       text-white font-medium py-2 px-4 rounded-lg
                       text-sm transition-colors"
          >
            📝 Manual Input
          </button>

        </div>
      </div>
    </header>
  )
}