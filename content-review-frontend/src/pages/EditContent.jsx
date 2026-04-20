import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { Save, ChevronRight, X, Info } from 'lucide-react';
import api from '../services/api';
import './CreateContent.css';

const EditContent = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    title: '',
    body: ''
  });
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    const fetchContent = async () => {
      try {
        const data = await api.get(`/content/${id}`);
        setFormData({
          title: data.content.title,
          body: data.content.body
        });
      } catch (error) {
        console.error('Failed to fetch content:', error);
      } finally {
        setLoading(false);
      }
    };
    fetchContent();
  }, [id]);

  const handleUpdate = async (e) => {
    e.preventDefault();
    setSaving(true);
    try {
      await api.put(`/content/${id}`, formData);
      navigate(`/content/${id}`);
    } catch (error) {
      alert('Update failed: ' + error.message);
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <div className="container" style={{ padding: '4rem', textAlign: 'center' }}>Loading content...</div>;

  return (
    <div className="create-page animate-in">
      <div className="create-header">
        <div className="header-breadcrumbs">
          <span>Workspace</span>
          <ChevronRight size={12} />
          <span className="current">Edit & Resubmit</span>
        </div>
        <div className="header-main-actions">
          <button type="button" className="btn-ghost" onClick={() => navigate(-1)}>
            Cancel
          </button>
          <button type="submit" form="edit-form" className="btn-premium" disabled={saving}>
            <Save size={16} /> {saving ? 'Resubmitting...' : 'Resubmit for Review'}
          </button>
        </div>
      </div>

      <div className="create-layout">
        <div className="editor-section">
          <form id="edit-form" className="create-form-luxe" onSubmit={handleUpdate}>
            <div className="input-field-group">
              <input
                type="text"
                className="luxe-title-input"
                placeholder="Content Title"
                value={formData.title}
                onChange={(e) => setFormData({ ...formData, title: e.target.value })}
                required
              />
            </div>

            <div className="editor-container">
              <textarea
                className="luxe-body-editor"
                placeholder="Update your content..."
                value={formData.body}
                onChange={(e) => setFormData({ ...formData, body: e.target.value })}
                required
              ></textarea>
            </div>
          </form>
        </div>

        <aside className="assets-sidebar">
          <div className="sidebar-group info">
            <div className="group-label">RE-SUBMISSION INFO</div>
            <div className="workflow-hint" style={{ background: 'rgba(255, 59, 48, 0.05)', borderLeftColor: 'var(--rejected)' }}>
              <Info size={14} style={{ marginBottom: '8px', display: 'block' }} />
              Editing this content will reset the approval workflow. It will start again from <strong>Stage 1 (Editorial Review)</strong>.
            </div>
          </div>
        </aside>
      </div>
    </div>
  );
};

export default EditContent;
