import { useState } from 'react'
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from '@/components/ui/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'
import { Plus } from 'lucide-react'
import { useCreateProject } from '@/hooks/queries'
import { useNavigate } from 'react-router-dom'

interface Props {
  open?: boolean
  onOpenChange?: (open: boolean) => void
  trigger?: React.ReactNode
}

export function NewProjectDialog({ open: openProp, onOpenChange, trigger }: Props = {}) {
  const [internalOpen, setInternalOpen] = useState(false)
  const controlled = openProp !== undefined
  const open = controlled ? Boolean(openProp) : internalOpen
  const setOpen = (v: boolean) => {
    if (controlled) onOpenChange?.(v)
    else setInternalOpen(v)
  }

  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [authorized, setAuthorized] = useState(false)
  const [authRef, setAuthRef] = useState('')
  const [error, setError] = useState<string | null>(null)
  const create = useCreateProject()
  const navigate = useNavigate()

  const reset = () => {
    setName('')
    setDescription('')
    setAuthorized(false)
    setAuthRef('')
    setError(null)
  }

  const onSubmit = async () => {
    setError(null)
    if (!name.trim()) return setError('Name is required')
    if (authorized && !authRef.trim()) {
      return setError('Authorization reference is required for authorized projects')
    }
    try {
      const created = await create.mutateAsync({
        name: name.trim(),
        description: description.trim() || undefined,
        authorized_use: authorized,
        authorization_ref: authorized ? authRef.trim() : null,
      })
      reset()
      setOpen(false)
      navigate(`/projects/${created.id}`)
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Create failed')
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={(v) => {
        if (!v) reset()
        setOpen(v)
      }}
    >
      {trigger && <DialogTrigger asChild>{trigger}</DialogTrigger>}
      <DialogContent>
        <DialogHeader>
          <DialogTitle>New research project</DialogTitle>
          <DialogDescription>
            A project groups targets, research runs, evidence and findings. Authorized projects can upload
            samples and run Lab experiments.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">Name</label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Windows kernel driver audit 2026 Q3"
            />
          </div>
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">Description</label>
            <Input value={description} onChange={(e) => setDescription(e.target.value)} placeholder="optional" />
          </div>
          <div className="flex items-center justify-between rounded-lg border border-white/5 bg-white/[0.02] px-3 py-2">
            <div>
              <div className="text-sm font-medium">Authorized for research</div>
              <div className="text-xs text-muted-foreground">
                Required to upload samples and run Lab experiments.
              </div>
            </div>
            <Switch checked={authorized} onCheckedChange={(v) => setAuthorized(Boolean(v))} />
          </div>
          {authorized && (
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground">Authorization reference</label>
              <Input
                value={authRef}
                onChange={(e) => setAuthRef(e.target.value)}
                placeholder="e.g. ticket #ABC-123 or contract ref"
              />
            </div>
          )}
          {error && <p className="text-[11px] text-rose-400">{error}</p>}
        </div>
        <DialogFooter>
          <Button type="button" variant="ghost" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button onClick={onSubmit} disabled={create.isPending}>
            {create.isPending ? 'Creating…' : 'Create project'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
