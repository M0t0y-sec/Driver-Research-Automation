import { Link } from 'react-router-dom'
import { Button } from '@/components/ui/button'
import { Compass } from 'lucide-react'

export default function NotFoundPage() {
  return (
    <div className="flex min-h-[50vh] flex-col items-center justify-center text-center">
      <Compass className="h-10 w-10 text-muted-foreground/60" />
      <h1 className="mt-4 text-2xl font-semibold">Not found</h1>
      <p className="mt-2 max-w-md text-sm text-muted-foreground">
        The page you requested does not exist, or the resource has been archived.
      </p>
      <Link to="/dashboard" className="mt-4">
        <Button variant="outline" size="sm">Back to dashboard</Button>
      </Link>
    </div>
  )
}
