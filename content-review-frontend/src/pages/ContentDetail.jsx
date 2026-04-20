import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { ArrowLeft, Check, X, Clock, User, Calendar, FileText, ChevronRight, Plus, Send } from 'lucide-react';
import api from '../services/api';
import { useAuth } from '../context/AuthContext';
import './ContentDetail.css';

const ContentDetail = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const { user } = useAuth();

  const [content, setContent] = useState(null);
  const [loading, setLoading] = useState(true);
  const [subContent, setSubContent] = useState([]);
  const [reviewComment, setReviewComment] = useState('');
  const [actionLoading, setActionLoading] = useState(false);
  const [decision, setDecision] = useState('');

  useEffect(() => {
    const fetchDetail = async () => {
      try {
        const data = await api.get(`/content/${id}`);
        setContent({
          ...data.content,
          history: data.history || []
        });
        setSubContent(data.subContent || []);
      } catch (error) {
        console.error('Failed to fetch details:', error);
      } finally {
        setLoading(false);
      }
    };
    fetchDetail();
  }, [id]);

  const handleAction = async () => {
    if (!decision) {
      alert('Please select a decision.');
      return;
    }
    if (decision === 'reject' && !reviewComment.trim()) {
      alert('A comment is required for rejection.');
      return;
    }

    setActionLoading(true);
    try {
      const endpoint = decision === 'approve' ? `/review/${id}/approve` : `/review/${id}/reject`;
      await api.post(endpoint, {
        comment: reviewComment
      });
      const data = await api.get(`/content/${id}`);
      setContent({
        ...data.content,
        history: data.history || []
      });
      setSubContent(data.subContent || []);
      setDecision('');
      setReviewComment('');
    } catch (error) {
      alert(`Action failed: ${error.message}`);
    } finally {
      setActionLoading(false);
    }
  };

  if (loading) return <div className="container" style={{ padding: '4rem', textAlign: 'center', color: 'var(--muted)' }}>Analyzing content...</div>;
  if (!content) return <div className="container" style={{ padding: '4rem', textAlign: 'center' }}>Resource not available.</div>;

  const isReviewer = user?.role === 'reviewer_l1' || user?.role === 'admin' || user?.role === 'reviewer_l2';
  const showReviewPanel = content.status === 'pending_review' && isReviewer;

  return (
    <div className="detail-page animate-in">
      <div className="detail-container">
        <div className="header-actions">
          <button className="back-link" onClick={() => navigate(-1)}>
            ← Back to list
          </button>

          {content.status === 'rejected' && user?.role === 'creator' && (
            <button className="btn-primary-sm" onClick={() => navigate(`/edit/${content.id}`)}>
              Edit & Resubmit
            </button>
          )}
        </div>

        <div className="detail-header-section">
          <h2>{content.title}</h2>
          <div className="header-meta">
            <span className={`badge-luxe badge-${content.status === 'pending_review' ? 'pending' : content.status}`}>
              {content.status.replace('_', ' ')}
            </span>
            <span className="meta-item">by {content.creator_name || 'System'}</span>
            <span className="meta-item">Created {new Date(content.updated_at).toLocaleDateString()}</span>
            <span className="meta-item">v{content.version}</span>
          </div>
        </div>

        <div className="card stepper-card mb-24">
          <div className="card-label">APPROVAL PROGRESS</div>
          <div className="horizontal-stepper">
            <div className={`h-step ${content.current_stage > 1 || content.status === 'approved' ? 'done' : 'active'}`}>
              <div className="h-circle">{content.current_stage > 1 || content.status === 'approved' ? '1' : '1'}</div>
              <div className="h-label-wrap">
                <div className="h-title">Editorial Review</div>
                <div className="h-status">{content.current_stage > 1 || content.status === 'approved' ? 'Approved' : 'In progress'}</div>
              </div>
            </div>

            <div className={`h-connector ${content.current_stage > 1 || content.status === 'approved' ? 'done' : ''}`}></div>

            <div className={`h-step ${content.status === 'approved' ? 'done' : content.current_stage === 2 ? 'active' : ''}`}>
              <div className="h-circle">2</div>
              <div className="h-label-wrap">
                <div className="h-title">Final Approval</div>
                <div className="h-status">{content.status === 'approved' ? 'Approved' : content.current_stage === 2 ? 'In progress' : 'Waiting'}</div>
              </div>
            </div>

            <div className={`h-connector ${content.status === 'approved' ? 'done' : ''}`}></div>

            <div className={`h-step ${content.status === 'approved' ? 'done' : ''}`}>
              <div className="h-circle">✓</div>
              <div className="h-label-wrap">
                <div className="h-title">Published</div>
                <div className="h-status">{content.status === 'approved' ? 'Final' : 'Waiting'}</div>
              </div>
            </div>
          </div>
        </div>

        <div className="detail-main-grid">
          <div className="detail-col-content">
            <div className="card mb-24">
              <div className="card-header-simple">
                <h3>Content</h3>
              </div>
              <div className="card-body">
                <div className="content-view-box">
                  {content.body}
                </div>
              </div>
            </div>

            <div className="card">
              <div className="card-header-simple flex-between">
                <h3>Sub-content</h3>
              </div>
              <div className="sub-content-list">
                {subContent.length > 0 ? subContent.map(sub => (
                  <div key={sub.id} className="sub-item-row">
                    <div className="sub-item-info">
                      <span className="sub-item-title">{sub.title}</span>
                      <span className="sub-item-meta">sub-content · {sub.status}</span>
                    </div>
                  </div>
                )) : (
                  <div className="empty-subs">No associated assets found.</div>
                )}
              </div>
            </div>
          </div>

          <div className="detail-col-sidebar">
            {showReviewPanel && (
              <div className="review-action-panel card mb-20">
                <div className="review-panel-head">
                  <Clock size={14} /> Awaiting your review — Stage {content.current_stage}
                </div>
                <div className="review-panel-body">
                  <div className="form-group-luxe">
                    <label>DECISION</label>
                    <select value={decision} onChange={(e) => setDecision(e.target.value)}>
                      <option value="">Select decision...</option>
                      <option value="approve">Approve</option>
                      <option value="reject">Reject</option>
                    </select>
                  </div>
                  <div className="form-group-luxe">
                    <label>COMMENT</label>
                    <textarea
                      placeholder="Add review notes..."
                      value={reviewComment}
                      onChange={(e) => setReviewComment(e.target.value)}
                    ></textarea>
                  </div>
                  <div className="review-btn-row">
                    <button className="btn-green-sm" onClick={handleAction} disabled={actionLoading}>
                      {actionLoading ? 'Processing...' : 'Approve'}
                    </button>
                    <button className="btn-red-sm" onClick={handleAction} disabled={actionLoading}>
                      Reject
                    </button>
                  </div>
                </div>
              </div>
            )}

            <div className="card">
              <div className="card-header-simple">
                <h3>Review History</h3>
              </div>
              <div className="card-body p-0">
                <div className="history-list">
                  <div className="history-item">
                    <div className="history-icon-circle">→</div>
                    <div className="history-details">
                      <div className="history-title">Submitted for review</div>
                      <div className="history-meta">{content.creator_name || 'System'} · v{content.version}</div>
                    </div>
                  </div>
                  {content.history?.map((log, idx) => {
                    const isApprove = log.decision === 'approved';
                    const stageNum = log.stage_id === 'a1000000-0000-0000-0000-000000000002' ? 2 : 1;
                    return (
                      <div key={idx} className="history-item">
                        <div className={`history-icon-circle ${isApprove ? 'success' : 'fail'}`}>
                          {isApprove ? '✓' : '✕'}
                        </div>
                        <div className="history-details">
                          <div className="history-title">{isApprove ? 'Approved' : 'Rejected'} at Stage {stageNum}</div>
                          <div className="history-meta">{log.reviewer_name || 'Reviewer'} · v{content.version}</div>
                          {log.comment && <div className="history-comment">"{log.comment}"</div>}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default ContentDetail;
