import { useRef, useState } from 'react'
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
import { Upload, FileUp } from 'lucide-react'
import { useUploadTarget, useProjects } from '@/hooks/queries'
import { toast } from '@/components/common/Toaster'

interface Props {
  projectId?: string
  open?: boolean
  onOpenChange?: (open: boolean) => void
  trigger?: React.ReactNode
  onUploaded?: (targetId: string) => void
}

export function NewTargetDialog({ projectId, open: openProp, onOpenChange, trigger, onUploaded }: Props = {}) {
  const [internalOpen, setInternalOpen] = useState(false)
  const controlled = openProp !== undefined
  const open = controlled ? Boolean(openProp) : internalOpen
  const setOpen = (v: boolean) => {
    if (controlled) onOpenChange?.(v)
    else setInternalOpen(v)
  }

  const projects = useProjects()
  const upload = useUploadTarget()
  const [selectedProject, setSelectedProject] = useState(projectId ?? '')
  const [name, setName] = useState('')
  const fileRef = useRef<HTMLInputElement>(null)
  const [file, setFile] = useState<File | null>(null)
  const [error, setError] = useState<string | null>(null)

  const reset = () => {
    setFile(null)
    setName('')
    setError(null)
    if (fileRef.current) fileRef.current.value = ''
    if (!projectId) setSelectedProject('')
  }

  const onSubmit = async () => {
    setError(null)
    const pid = projectId ?? selectedProject
    if (!pid) return setError('Pick a project first')
    if (!file) return setError('Select a sample file')
    try {
      const target = await upload.mutateAsync({
        project_id: pid,
        name: name.trim() || file.name,
        file,
      })
      toast('Sample uploaded and hashed')
      reset()
      setOpen(false)
      onUploaded?.(target.id)
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : 'Upload failed'
      setError(msg)
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
          <DialogTitle>Upload driver sample</DialogTitle>
          <DialogDescription>
            Files are content-hashed (sha256) and stored under the artefact store. Only authorized projects can
            accept uploads.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-3">
          {!projectId && (
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground">Project</label>
              <select
                className="w-full rounded-md border border-white/10 bg-white/[0.03] px-3 py-2 text-sm"
                value={selectedProject}
                onChange={(e) => setSelectedProject(e.target.value)}
              >
                <option value="">— select —</option>
                {(projects.data ?? [])
                  .filter((p) => p.authorized_use)
                  .map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.name} · {p.id}
                    </option>
                  ))}
              </select>
            </div>
          )}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">Display name</label>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="optional" />
          </div>
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground">Sample file</label>
            <input
              ref={fileRef}
              type="file"
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              className="block w-full text-xs file:mr-3 file:rounded file:border file:border-white/10 file:bg-white/[0.05] file:px-3 file:py-1.5 file:text-foreground"
            />
            {file && (
              <p className="text-[11px] text-muted-foreground">
                <FileUp className="mr-1 inline h-3 w-3" />
                {file.name} · {file.size} bytes
              </p>
            )}
          </div>
          {error && <p className="text-[11px] text-rose-400">{error}</p>}
        </div>
        <DialogFooter>
          <Button type="button" variant="ghost" onClick={() => setOpen(false)}>
            Cancel
          </Button>
          <Button onClick={onSubmit} disabled={upload.isPending}>
            <Upload className="h-3.5 w-3.5" />
            {upload.isPending ? 'Uploading…' : 'Upload'}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}
