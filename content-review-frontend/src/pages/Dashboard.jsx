import React, { useState, useEffect } from 'react';
import { FileText, Clock, CheckCircle, XCircle, Send } from 'lucide-react';
import api from '../services/api';
import './Dashboard.css';

const Dashboard = () => {
  const [content, setContent] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const data = await api.get('/content');
        setContent(data);
      } catch (error) {
        console.error('Error fetching dashboard data:', error);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  const stats = [
    { label: 'Total', value: content.length, sub: 'items tracked', color: 'var(--text)', icon: <FileText size={14} /> },
    { label: 'Pending', value: content.filter(c => c.status === 'pending_review').length, sub: 'awaiting action', color: 'var(--pending)', icon: <Clock size={14} /> },
    { label: 'Approved', value: content.filter(c => c.status === 'approved').length, sub: 'completed items', color: 'var(--approved)', icon: <CheckCircle size={14} /> },
    { label: 'Rejected', value: content.filter(c => c.status === 'rejected').length, sub: 'needs attention', color: 'var(--rejected)', icon: <XCircle size={14} /> },
  ];

  const recentActivity = content.slice(0, 5);
  const pendingContent = content.filter(c => c.status === 'pending_review');

  return (
    <div className="dashboard">
      <div className="stats-row">
        {stats.map((stat, i) => (
          <div key={i} className="stat-card">
            <div className="stat-label">{stat.label}</div>
            <div className="stat-value" style={{ color: stat.color }}>{stat.value}</div>
            <div className="stat-sub">{stat.sub}</div>
          </div>
        ))}
      </div>

      <div className="dashboard-grid">
        <div className="card">
          <div className="card-header">
            <h3>Recent Activity</h3>
            <button className="text-btn" onClick={() => window.location.href = '/content'}>View all</button>
          </div>
          <div className="table-wrap">
            <table className="mini-table">
              <thead>
                <tr>
                  <th>Title</th>
                  <th>Status</th>
                  <th>Stage</th>
                  <th>Updated</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr><td colSpan="4" style={{ textAlign: 'center' }}>Loading...</td></tr>
                ) : recentActivity.map(item => (
                  <tr key={item.id}>
                    <td className="td-title text-truncate">{item.title}</td>
                    <td><span className={`badge badge-${item.status.includes('pending') ? 'pending' : item.status}`}>{item.status.replace('_', ' ')}</span></td>
                    <td><span className="stage-pill">Stage {item.current_stage}</span></td>
                    <td className="td-meta">{new Date(item.updated_at).toLocaleDateString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <h3>Pending Your Review</h3>
          </div>
          <div className="card-body scrollable">
            <div className="pending-list">
              {loading ? (
                <div style={{ padding: '20px', textAlign: 'center', fontSize: '13px' }}>Loading...</div>
              ) : pendingContent.length === 0 ? (
                <div style={{ padding: '20px', textAlign: 'center', fontSize: '13px', color: 'var(--muted)' }}>No items pending review.</div>
              ) : pendingContent.map(item => (
                <div
                  key={item.id}
                  className="pending-item"
                  onClick={() => window.location.href = `/content/${item.id}`}
                >
                  <div className="pending-info">
                    <span className="pending-title">{item.title}</span>
                    <span className="pending-meta">v{item.version} · {new Date(item.updated_at).toLocaleDateString()}</span>
                  </div>
                  <span className="badge-pill">Stage {item.current_stage}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
