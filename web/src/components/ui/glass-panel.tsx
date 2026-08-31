import * as React from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const glassPanelVariants = cva('rounded-2xl', {
  variants: {
    variant: {
      default: 'glass',
      elevated: 'glass-elevated',
      subtle: 'glass-subtle',
    },
    interactive: {
      true: 'glass-interactive cursor-pointer',
      false: '',
    },
  },
  defaultVariants: {
    variant: 'default',
    interactive: false,
  },
})

export interface GlassPanelProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof glassPanelVariants> {}

const GlassPanel = React.forwardRef<HTMLDivElement, GlassPanelProps>(
  ({ className, variant, interactive, ...props }, ref) => (
    <div ref={ref} className={cn(glassPanelVariants({ variant, interactive }), className)} {...props} />
  ),
)
GlassPanel.displayName = 'GlassPanel'

export { GlassPanel, glassPanelVariants }
