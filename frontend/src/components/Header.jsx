// ============================================================
// src/components/Header.jsx
// Top navigation bar — connection status + action buttons
// Mobile: icon-only buttons, no logo, no subtitle
// Desktop: full labels and layout
// ============================================================

export function Header({ isConnected, onOpenManualInput, onOpenDemo }) {
  return (
    <header className="bg-slate-800 border-b border-slate-700 px-3 sm:px-6 py-3 sm:py-4">
      <div className="max-w-7xl mx-auto flex items-center justify-between gap-2">

        {/* Left — Logo + Title */}
        <div className="flex items-center gap-2 sm:gap-3">
          <div className="text-xl sm:text-2xl">🛡️</div>
          <div>
            <h1 className="text-sm sm:text-xl font-bold text-white">NIDS SOC Dashboard</h1>
            <p className="text-xs text-slate-400">Real-Time Network Intrusion Detection</p>
          </div>
        </div>

        {/* Right — Status + Buttons */}
        <div className="flex items-center gap-2 sm:gap-4">

          {/* Connection Status */}
          <div className="flex items-center gap-1.5 sm:gap-2">
            <div className="relative flex items-center justify-center">
              {isConnected && (
                <div className="absolute w-2.5 h-2.5 sm:w-3 sm:h-3 bg-green-400 rounded-full animate-ping opacity-75" />
              )}
              <div className={`w-2.5 h-2.5 sm:w-3 sm:h-3 rounded-full ${
                isConnected ? 'bg-green-400' : 'bg-red-500'
              }`} />
            </div>
            <span className={`text-xs sm:text-sm font-medium ${
              isConnected ? 'text-green-400' : 'text-red-400'
            }`}>
              {isConnected ? 'Live' : 'Off'}
            </span>
          </div>

          {/* Demo Video Button — icon only on mobile */}
          <button
            id="demo-video-btn"
            onClick={onOpenDemo}
            title="Demo Video"
            className="w-8 h-8 sm:w-auto sm:h-auto flex items-center justify-center
                       sm:gap-2 bg-slate-700 hover:bg-slate-600
                       text-white font-medium sm:py-2 sm:px-4 rounded-lg
                       text-sm transition-colors border border-slate-600"
          >
            🎬<span className="hidden sm:inline ml-1.5">Demo</span>
          </button>

          {/* Manual Input Button — icon only on mobile */}
          <button
            id="manual-input-btn"
            onClick={onOpenManualInput}
            title="Manual Prediction Input"
            className="w-8 h-8 sm:w-auto sm:h-auto flex items-center justify-center
                       sm:gap-2 bg-blue-600 hover:bg-blue-700
                       text-white font-medium sm:py-2 sm:px-4 rounded-lg
                       text-sm transition-colors"
          >
            📝<span className="hidden sm:inline ml-1.5">Manual Input</span>
          </button>

        </div>
      </div>
    </header>
  )
}
