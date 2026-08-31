import { useEffect, useState } from 'react'

// Minimal toast system (shadcn-style usage, no extra dependency)

type Toast = { id: number; message: string }

let pushToast: ((message: string) => void) | null = null

export function toast(message: string) {
  pushToast?.(message)
}

export function Toaster() {
  const [items, setItems] = useState<Toast[]>([])

  useEffect(() => {
    pushToast = (message: string) => {
      const id = Date.now() + Math.random()
      setItems((prev) => [...prev, { id, message }])
      setTimeout(() => setItems((prev) => prev.filter((t) => t.id !== id)), 2600)
    }
    return () => {
      pushToast = null
    }
  }, [])

  return (
    <div className="pointer-events-none fixed bottom-4 right-4 z-[100] flex flex-col gap-2">
      {items.map((t) => (
        <div
          key={t.id}
          className="pointer-events-auto rounded-md border bg-card px-3 py-2 text-xs shadow-lg"
        >
          {t.message}
        </div>
      ))}
    </div>
  )
}
