import { useState, useCallback } from 'react'

//  Constants 
const MAX_TOASTS   = 3
const DEFAULT_DURATION = 4000

// useToast 
// Returns: { toasts, addToast, removeToast }
// toasts: array of { id, message, type, duration }
// type: 'success' | 'error' | 'warning' | 'info'
export function useToast() {
  const [toasts, setToasts] = useState([])

  // removeToast 
  const removeToast = useCallback((id) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

  // addToast 
  const addToast = useCallback((message, type = 'info', duration = DEFAULT_DURATION, title = null) => {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`

    const newToast = { id, message, type, duration, title }

    setToasts(prev => {
      // If at max capacity, evict the oldest (first in array)
      const trimmed = prev.length >= MAX_TOASTS ? prev.slice(1) : prev
      return [...trimmed, newToast]
    })

    // Auto-remove after duration
    setTimeout(() => {
      removeToast(id)
    }, duration)

    return id
  }, [removeToast])

  return { toasts, addToast, removeToast }
}