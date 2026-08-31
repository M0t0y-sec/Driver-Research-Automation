import { createBrowserRouter, Navigate, useParams } from 'react-router-dom'
import { AppLayout } from '@/components/layout/AppLayout'

import DashboardPage from '@/pages/dashboard/DashboardPage'
import ProjectsPage from '@/pages/projects/ProjectsPage'
import ProjectDetailPage from '@/pages/projects/ProjectDetailPage'
import TargetsPage from '@/pages/targets/TargetsPage'
import TargetDetailPage from '@/pages/targets/TargetDetailPage'
import HypothesesPage from '@/pages/hypotheses/HypothesesPage'
import HypothesisDetailPage from '@/pages/hypotheses/HypothesisDetailPage'
import ExperimentsPage from '@/pages/experiments/ExperimentsPage'
import ExperimentDetailPage from '@/pages/experiments/ExperimentDetailPage'
import RunsPage from '@/pages/research/RunsPage'
import ResearchRunPage from '@/pages/research/ResearchRunPage'
import FindingsPage from '@/pages/findings/FindingsPage'
import FindingDetailPage from '@/pages/findings/FindingDetailPage'
import EvidencePage from '@/pages/evidence/EvidencePage'
import EvidenceDetailPage from '@/pages/evidence/EvidenceDetailPage'
import DetectionPage from '@/pages/detection/DetectionPage'
import LabPage from '@/pages/lab/LabPage'
import ApprovalsPage from '@/pages/approvals/ApprovalsPage'
import QAReviewsPage from '@/pages/qa/QAReviewsPage'
import AgentsPage from '@/pages/agents/AgentsPage'
import ToolsPage from '@/pages/agents/ToolsPage'
import SettingsPage from '@/pages/settings/SettingsPage'
import NotFoundPage from '@/pages/NotFoundPage'

function FindingTabRedirect({ tab }: { tab: 'evidence' | 'replay' }) {
  const { id } = useParams<{ id: string }>()
  return <Navigate to={`/findings/${id}?tab=${tab}`} replace />
}

export const router = createBrowserRouter([
  {
    element: <AppLayout />,
    children: [
      { path: '/', element: <Navigate to="/dashboard" replace /> },
      { path: '/dashboard', element: <DashboardPage /> },

      { path: '/projects', element: <ProjectsPage /> },
      { path: '/projects/:projectId', element: <ProjectDetailPage /> },

      { path: '/targets', element: <TargetsPage /> },
      { path: '/targets/:id', element: <TargetDetailPage /> },

      { path: '/hypotheses', element: <HypothesesPage /> },
      { path: '/hypotheses/:id', element: <HypothesisDetailPage /> },

      { path: '/experiments', element: <ExperimentsPage /> },
      { path: '/experiments/:id', element: <ExperimentDetailPage /> },

      { path: '/research/runs', element: <RunsPage /> },
      { path: '/research/runs/:id', element: <ResearchRunPage /> },
      { path: '/research/:id', element: <ResearchRunPage /> },

      { path: '/findings', element: <FindingsPage /> },
      { path: '/findings/:id', element: <FindingDetailPage /> },
      { path: '/findings/:id/evidence-chain', element: <FindingTabRedirect tab="evidence" /> },
      { path: '/findings/:id/replay-bundle', element: <FindingTabRedirect tab="replay" /> },

      { path: '/evidence', element: <EvidencePage /> },
      { path: '/evidence/:id', element: <EvidenceDetailPage /> },

      { path: '/detection', element: <DetectionPage /> },

      { path: '/lab', element: <LabPage /> },

      { path: '/approvals', element: <ApprovalsPage /> },
      { path: '/qa', element: <QAReviewsPage /> },

      { path: '/agents', element: <AgentsPage /> },
      { path: '/agents/tools', element: <ToolsPage /> },

      { path: '/settings', element: <SettingsPage /> },
      { path: '*', element: <NotFoundPage /> },
    ],
  },
])
