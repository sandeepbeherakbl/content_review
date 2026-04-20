export const STATUSES = {
  DRAFT: 'draft',
  PENDING_STAGE_1: 'pending_stage_1',
  PENDING_STAGE_2: 'pending_stage_2',
  APPROVED: 'approved',
  REJECTED: 'rejected'
};

export const STAGES = [
  { id: 1, name: 'Editorial Review', role: 'reviewer_1' },
  { id: 2, name: 'Final Approval', role: 'reviewer_2' }
];

export const mockContent = [
  {
    id: '1',
    title: 'Modern Web Architecture 2026',
    description: 'A deep dive into the latest patterns and practices for building high-performance web applications in 2026.',
    createdBy: 'Sandeep',
    createdAt: '2026-04-10T10:00:00Z',
    status: STATUSES.APPROVED,
    currentStage: 3, 
    subContent: [
      { id: 's1', title: 'Header Video Asset', type: 'video', status: 'approved' },
      { id: 's2', title: 'Infographic Concept', type: 'image', status: 'approved' }
    ],
    history: [
      { action: 'Created', user: 'Sandeep', date: '2026-04-10T10:00:00Z' },
      { action: 'Approved Stage 1', user: 'Editor John', date: '2026-04-11T14:30:00Z' },
      { action: 'Approved Final', user: 'Admin Sarah', date: '2026-04-12T09:15:00Z' }
    ]
  },
  {
    id: '2',
    title: 'The Future of AI Agents',
    description: 'Exploring how autonomous agents are transforming the software development lifecycle.',
    createdBy: 'Sandeep',
    createdAt: '2026-04-15T11:20:00Z',
    status: STATUSES.PENDING_STAGE_1,
    currentStage: 1,
    history: [
      { action: 'Created', user: 'Sandeep', date: '2026-04-15T11:20:00Z' }
    ]
  },
  {
    id: '3',
    title: 'Luxury UI Design Principles',
    description: 'Understanding the psychology of premium aesthetics in digital products.',
    createdBy: 'Sandeep',
    createdAt: '2026-04-18T16:45:00Z',
    status: STATUSES.REJECTED,
    currentStage: 1,
    rejectionComment: 'The tone is a bit too technical. Needs more focus on visual examples.',
    history: [
      { action: 'Created', user: 'Sandeep', date: '2026-04-18T16:45:00Z' },
      { action: 'Rejected at Stage 1', user: 'Editor John', date: '2026-04-19T10:00:00Z', comment: 'The tone is a bit too technical. Needs more focus on visual examples.' }
    ]
  }
];
