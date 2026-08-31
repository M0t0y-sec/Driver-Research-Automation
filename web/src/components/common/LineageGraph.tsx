import { useMemo } from 'react'
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Node,
  Edge,
  Position,
  ReactFlowProvider,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { metaFor } from './lineageMeta'
import { idShort } from '@/lib/idPath'
import type { Lineage, LineageNode } from '@/types'

// Build a simple left-to-right DAG from the lineage list, ordered by
// the canonical chain: target → observation → hypothesis → experiment
// → execution → crash → evidence → finding → qa_review.

const ORDER: string[] = [
  'project',
  'target',
  'observation',
  'attack_surface',
  'hypothesis',
  'experiment',
  'execution',
  'crash',
  'evidence',
  'qa_review',
  'finding',
  'research',
  'visibility',
  'detection',
  'robustness',
  'tool_run',
]

function rank(type: string): number {
  const i = ORDER.indexOf(type)
  return i === -1 ? ORDER.length : i
}

function toFlow(lineage: Lineage): { nodes: Node[]; edges: Edge[] } {
  const sorted = [...lineage.nodes].sort((a, b) => rank(a.type) - rank(b.type))
  const COL_X = 240
  const ROW_Y = 110
  const lanes: Record<string, number> = {}
  const positions: Record<string, { x: number; y: number }> = {}

  sorted.forEach((n) => {
    const col = rank(n.type)
    const lane = lanes[n.type] ?? 0
    lanes[n.type] = lane + 1
    positions[n.id] = { x: col * COL_X, y: lane * ROW_Y }
  })

  const nodes: Node[] = sorted.map((n) => {
    const meta = metaFor(n.type)
    return {
      id: n.id,
      type: 'default',
      position: positions[n.id],
      sourcePosition: Position.Right,
      targetPosition: Position.Left,
      data: {
        label: (
          <div className="min-w-[180px] text-left">
            <div className={`text-[10px] font-semibold uppercase tracking-wider ${meta.color}`}>
              {meta.label}
            </div>
            <div className="font-mono text-[12px] text-foreground/90">{idShort(n.id)}</div>
            {n.label && (
              <div className="mt-0.5 max-w-[260px] truncate text-[10px] text-muted-foreground" title={n.label}>
                {n.label}
              </div>
            )}
          </div>
        ),
      },
      style: {
        background: 'rgba(255,255,255,0.04)',
        border: '1px solid rgba(255,255,255,0.10)',
        borderRadius: 10,
        padding: 4,
        color: '#e5e7eb',
        width: 220,
      },
    }
  })

  const edges: Edge[] = []
  for (let i = 0; i < sorted.length - 1; i++) {
    const a = sorted[i]
    const b = sorted[i + 1]
    edges.push({
      id: `${a.id}-${b.id}`,
      source: a.id,
      target: b.id,
      animated: a.type === 'hypothesis' || a.type === 'experiment',
      style: { stroke: 'rgba(148,163,184,0.4)', strokeWidth: 1.2 },
    })
  }
  return { nodes, edges }
}

function Inner({ lineage }: { lineage: Lineage }) {
  const { nodes, edges } = useMemo(() => toFlow(lineage), [lineage])
  if (lineage.nodes.length === 0) {
    return (
      <div className="rounded-lg border border-dashed px-6 py-10 text-center text-xs text-muted-foreground">
        No lineage nodes recorded.
      </div>
    )
  }
  return (
    <div className="h-[420px] w-full overflow-hidden rounded-lg border bg-white/[0.02]">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        fitView
        proOptions={{ hideAttribution: true }}
        nodesDraggable
        nodesConnectable={false}
        elementsSelectable
        zoomOnDoubleClick
      >
        <Background gap={20} color="rgba(255,255,255,0.05)" />
        <Controls position="bottom-right" showInteractive={false} />
        <MiniMap pannable zoomable maskColor="rgba(0,0,0,0.6)" />
      </ReactFlow>
    </div>
  )
}

export function LineageGraph({ lineage }: { lineage: Lineage }) {
  return (
    <ReactFlowProvider>
      <Inner lineage={lineage} />
    </ReactFlowProvider>
  )
}
