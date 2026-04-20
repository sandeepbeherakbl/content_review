import React, { useState, useEffect } from 'react';
import { Clock, Eye, Trash2 } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import api from '../services/api';
import './Dashboard.css';

const PendingReview = () => {
  const [content, setContent] = useState([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchPending = async () => {
      try {
        const data = await api.get('/content?status=pending_review');
        setContent(data);
      } catch (error) {
        console.error('Failed to fetch pending review:', error);
      } finally {
        setLoading(false);
      }
    };
    fetchPending();
  }, []);

  return (
    <div className="content-list-page animate-in" style={{ padding: '0 40px' }}>
      <div className="page-header" style={{ marginBottom: '32px' }}>
        <h1 style={{ fontSize: '24px', fontWeight: 700, marginBottom: '8px' }}>Action Required</h1>
        <p style={{ color: 'var(--muted)', fontSize: '14px' }}>Items currently awaiting your editorial or final decision.</p>
      </div>

      <div className="card full-width">
        <div className="table-wrap">
          <table className="main-table">
            <thead>
              <tr>
                <th>Title</th>
                <th>Workflow Stage</th>
                <th>Version</th>
                <th>Last Modified</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan="5" style={{ textAlign: 'center', padding: '40px' }}>Analyzing pipeline...</td></tr>
              ) : content.length === 0 ? (
                <tr><td colSpan="5" style={{ textAlign: 'center', padding: '60px', color: 'var(--muted)' }}>
                  <Clock size={32} style={{ marginBottom: '12px', opacity: 0.3 }} />
                  <p>Your queue is empty. All items are reviewed.</p>
                </td></tr>
              ) : content.map((item) => (
                <tr key={item.id}>
                  <td className="td-title">{item.title}</td>
                  <td>
                    <div className="stage-pill" style={{ background: 'var(--pending-bg)', color: 'var(--pending)', border: 'none', fontWeight: 600 }}>
                      Stage {item.current_stage}
                    </div>
                  </td>
                  <td className="td-meta">v{item.version}</td>
                  <td className="td-meta">{new Date(item.updated_at).toLocaleDateString()}</td>
                  <td>
                    <button className="btn-primary-sm" onClick={() => navigate(`/content/${item.id}`)}>
                      <Eye size={12} /> Review
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default PendingReview;
