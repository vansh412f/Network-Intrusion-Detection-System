import React from 'react'

export function DemoVideoModal({ isOpen, onClose }) {
  if (!isOpen) return null

  const YOUTUBE_VIDEO_ID = "6TZZttQnAro"
  const embedUrl = `https://www.youtube.com/embed/${YOUTUBE_VIDEO_ID}?autoplay=1&rel=0`

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      {/* Backdrop overlay that closes modal when clicked */}
      <div 
        className="absolute inset-0 bg-slate-900/90 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Modal Container */}
      <div className="relative w-full max-w-4xl bg-slate-800 rounded-xl shadow-2xl border border-slate-700 overflow-hidden flex flex-col">
        
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-700 bg-slate-800/50">
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            🎬 Sensor.py Real Mode Demonstration on Local Host Network
          </h2>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white transition-colors p-1"
            title="Close"
          >
            <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Video Player Area */}
        <div className="w-full aspect-video bg-black flex items-center justify-center relative">
          {YOUTUBE_VIDEO_ID === "YOUR_YOUTUBE_ID_HERE" ? (
             <div className="text-center p-8 z-10">
               <div className="text-4xl mb-4">▶️</div>
               <h3 className="text-xl font-bold text-white mb-2">Awaiting YouTube Upload...</h3>
               
             </div>
          ) : (
            <iframe
              src={embedUrl}
              className="w-full h-full border-0 absolute inset-0"
              allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share"
              allowFullScreen
              title="NIDS Live Demo"
            ></iframe>
          )}
        </div>
      </div>
    </div>
  )
}
