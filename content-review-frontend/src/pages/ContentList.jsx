import React, { useState, useEffect } from 'react';
import { Search, Eye } from 'lucide-react';
import api from '../services/api';
import './ContentList.css';

const ContentList = () => {
  const [activeTab, setActiveTab] = useState('all');
  const [content, setContent] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchContent = async () => {
      setLoading(true);
      try {
        const query = activeTab === 'all' ? '' : `?status=${activeTab}`;
        const data = await api.get(`/content${query}`);
        setContent(data);
      } catch (error) {
        console.error('Failed to fetch content:', error);
      } finally {
        setLoading(false);
      }
    };
    fetchContent();
  }, [activeTab]);

  return (
    <div className="content-list-page">
      <div className="page-header">
        <div className="header-left">
          <h1>All Content</h1>
          <p>Browse and manage all items in the approval pipeline.</p>
        </div>
      </div>

      <div className="filters-bar">
        <div className="tabs mini">
          {['all', 'pending_review', 'approved', 'rejected'].map(tab => (
            <button 
              key={tab}
              className={`tab-btn ${activeTab === tab ? 'active' : ''}`}
              onClick={() => setActiveTab(tab)}
            >
              {tab.replace('_', ' ')}
            </button>
          ))}
        </div>
        <div className="search-wrap">
          <Search size={14} className="search-icon" />
          <input type="text" placeholder="Search content..." className="search-field" />
        </div>
      </div>

      <div className="card full-width">
        <div className="table-wrap">
          <table className="main-table">
            <thead>
              <tr>
                <th>Title</th>
                <th>Status</th>
                <th>Stage</th>
                <th>Version</th>
                <th>Updated</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan="6" style={{ textAlign: 'center', padding: '2rem' }}>Loading content...</td></tr>
              ) : content.length === 0 ? (
                <tr><td colSpan="6" style={{ textAlign: 'center', padding: '2rem' }}>No content found.</td></tr>
              ) : content.map((item) => (
                <tr key={item.id}>
                  <td className="td-title text-truncate">{item.title}</td>
                  <td><span className={`badge badge-${item.status.includes('pending') ? 'pending' : item.status}`}>{item.status.replace('_',' ')}</span></td>
                  <td><span className="stage-pill">{item.current_stage === 3 ? 'Done' : `Stage ${item.current_stage}`}</span></td>
                  <td className="td-meta">v{item.version}</td>
                  <td className="td-meta">{new Date(item.updated_at).toLocaleDateString()}</td>
                  <td>
                    <button className="icon-btn-lite" onClick={() => window.location.href = `/content/${item.id}`}><Eye size={14} /></button>
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

export default ContentList;
