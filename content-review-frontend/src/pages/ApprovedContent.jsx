import React, { useState, useEffect } from 'react';
import { CheckCircle, Eye, Send } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import api from '../services/api';
import './Dashboard.css';

const ApprovedContent = () => {
  const [content, setContent] = useState([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchApproved = async () => {
      try {
        const data = await api.get('/content?status=approved');
        setContent(data);
      } catch (error) {
        console.error('Failed to fetch approved content:', error);
      } finally {
        setLoading(false);
      }
    };
    fetchApproved();
  }, []);

  return (
    <div className="content-list-page animate-in" style={{ padding: '0 40px' }}>
      <div className="page-header" style={{ marginBottom: '32px' }}>
        <h1 style={{ fontSize: '24px', fontWeight: 700, marginBottom: '8px' }}>Asset Library</h1>
        <p style={{ color: 'var(--muted)', fontSize: '14px' }}>Approved versions ready for distribution or final publishing.</p>
      </div>

      <div className="card full-width">
        <div className="table-wrap">
          <table className="main-table">
            <thead>
              <tr>
                <th>Title</th>
                <th>Status</th>
                <th>Final Version</th>
                <th>Approval Date</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan="5" style={{ textAlign: 'center', padding: '40px' }}>Accessing archives...</td></tr>
              ) : content.length === 0 ? (
                <tr><td colSpan="5" style={{ textAlign: 'center', padding: '60px', color: 'var(--muted)' }}>
                  <CheckCircle size={32} style={{ marginBottom: '12px', opacity: 0.3 }} />
                  <p>No content has reached final approval yet.</p>
                </td></tr>
              ) : content.map((item) => (
                <tr key={item.id}>
                  <td className="td-title">{item.title}</td>
                  <td><span className="badge badge-approved">Approved</span></td>
                  <td className="td-meta">v{item.version}</td>
                  <td className="td-meta">{new Date(item.updated_at).toLocaleDateString()}</td>
                  <td>
                    <div style={{ display: 'flex', gap: '8px' }}>
                      <button className="btn-ghost btn-sm" onClick={() => navigate(`/content/${item.id}`)} title="View Details">
                        <Eye size={14} />
                      </button>
                      <button className="btn-primary-sm" title="Publish Version">
                         <Send size={12} /> Publish
                      </button>
                    </div>
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

export default ApprovedContent;
