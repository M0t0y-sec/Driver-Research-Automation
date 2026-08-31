// Generic helper: an open/close dialog state for any kind of modal trigger.
import { useState } from 'react'

export function useStartResearchDialog() {
  const [state, setState] = useState<{
    projectId: string | null
    targetId: string | null
    targetName: string | null
  }>({ projectId: null, targetId: null, targetName: null })

  return {
    ...state,
    open: (projectId: string, targetId: string, targetName?: string) =>
      setState({ projectId, targetId, targetName: targetName ?? null }),
    close: () => setState({ projectId: null, targetId: null, targetName: null }),
  }
}
