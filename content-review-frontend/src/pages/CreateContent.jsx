import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Save, Plus, Trash2, Link as LinkIcon, FileText, ChevronRight, X, CheckCircle, Sparkles, ArrowUp, Maximize2, Loader2 } from 'lucide-react';
import api from '../services/api';
import './CreateContent.css';

const SuccessModal = ({ onClose }) => (
  <div className="modal-overlay">
    <div className="modal-content animate-pop">
      <div className="modal-icon-wrap">
        <CheckCircle size={48} className="success-icon-luxe" />
      </div>
      <h2>Content Submitted</h2>
      <p>Your content and all associated assets have been successfully saved to the system.</p>
      <button className="btn-premium" onClick={onClose}>
        Go to Dashboard
      </button>
    </div>
  </div>
);

const CreateContent = () => {
  const navigate = useNavigate();
  const [formData, setFormData] = useState({
    title: '',
    body: '',
    subContent: []
  });
  const [loading, setLoading] = useState(false);
  const [showSuccess, setShowSuccess] = useState(false);
  const [aiTopic, setAiTopic] = useState('');
  const [isStreaming, setIsStreaming] = useState(false);

  const addSubContent = (type) => {
    const newItem = { id: Date.now(), title: '', type };
    setFormData({ ...formData, subContent: [...formData.subContent, newItem] });
  };

  const updateSubContent = (id, field, value) => {
    const updated = formData.subContent.map(item =>
      item.id === id ? { ...item, [field]: value } : item
    );
    setFormData({ ...formData, subContent: updated });
  };

  const removeSubContent = (id) => {
    setFormData({
      ...formData,
      subContent: formData.subContent.filter(item => item.id !== id)
    });
  };

  const handleSave = async (e) => {
    e.preventDefault();
    setLoading(true);
    try {
      const parentResponse = await api.post('/content', {
        title: formData.title,
        body: formData.body
      });

      const parentId = parentResponse.id;

      if (formData.subContent.length > 0) {
        for (const sub of formData.subContent) {
          await api.post('/sub-content', {
            parentId: parentId,
            title: sub.title,
            body: sub.type
          });
        }
      }

      setShowSuccess(true);
    } catch (error) {
      alert('Submission failed: ' + error.message);
    } finally {
      setLoading(false);
    }
  };

  const handleAiGenerate = async () => {
    if (!aiTopic || isStreaming) return;

    setIsStreaming(true);
    let accumulatedContent = '';

    try {
      const token = localStorage.getItem('token');
      const headers = {
        'Content-Type': 'application/json',
      };
      if (token) headers['Authorization'] = `Bearer ${token}`;

      const response = await fetch('http://localhost:5000/api/ai/generate-stream', {
        method: 'POST',
        headers,
        body: JSON.stringify({ topic: aiTopic }),
      });

      if (!response.ok) throw new Error('AI generation failed');

      const data = await response.json();
      const completionText = data.text;

      setFormData(prev => ({
        ...prev,
        body: '',
        title: prev.title || aiTopic
      }));

      let currentIdx = 0;
      const step = Math.max(1, Math.ceil(completionText.length / 100));

      const typeNext = () => {
        if (currentIdx < completionText.length) {
          currentIdx = Math.min(currentIdx + step, completionText.length);
          setFormData(prev => ({
            ...prev,
            body: completionText.substring(0, currentIdx)
          }));
          setTimeout(typeNext, 20);
        } else {
          setIsStreaming(false);
        }
      };

      if (completionText) {
        typeNext();
      } else {
        setIsStreaming(false);
      }
    } catch (error) {
      console.error('AI Generation Error:', error);
      alert('Failed to generate content: ' + error.message);
      setIsStreaming(false);
    }
  };

  return (
    <div className="create-page animate-in">
      {showSuccess && <SuccessModal onClose={() => navigate('/dashboard')} />}

      <div className="create-header">
        <div className="header-breadcrumbs">
          <span>Workspace</span>
          <ChevronRight size={12} />
          <span className="current">Create New</span>
        </div>
        <div className="header-main-actions">
          <button type="button" className="btn-ghost" onClick={() => navigate(-1)}>
            Discard
          </button>
          <button type="submit" form="create-form" className="btn-premium" disabled={loading}>
            <Save size={16} /> {loading ? 'Submitting...' : 'Submit Content'}
          </button>
        </div>
      </div>

      <div className="create-layout">
        <div className="editor-section">
          <form id="create-form" className="create-form-luxe" onSubmit={handleSave}>
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
                placeholder="Start writing your masterpiece..."
                value={formData.body}
                onChange={(e) => setFormData({ ...formData, body: e.target.value })}
                required
              ></textarea>

              <div className="ai-prompt-wrapper">
                <div className={`ai-prompt-bar ${isStreaming ? 'streaming' : ''}`}>
                  <div className="ai-bar-left">
                    <button type="button" className="ai-bar-icon-btn"><Sparkles size={18} className="ai-sparkle" /></button>
                  </div>

                  <input
                    type="text"
                    className="ai-topic-input"
                    placeholder="Ask AI to write a paragraph about..."
                    value={aiTopic}
                    onChange={(e) => setAiTopic(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && handleAiGenerate()}
                    disabled={isStreaming}
                  />

                  <div className="ai-bar-right">
                    <button
                      type="button"
                      className={`ai-send-btn ${aiTopic.trim() ? 'active' : ''} ${isStreaming ? 'loading' : ''}`}
                      onClick={handleAiGenerate}
                      disabled={!aiTopic.trim() || isStreaming}
                    >
                      {isStreaming ? <Loader2 size={18} className="animate-spin" /> : <ArrowUp size={20} />}
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </form>
        </div>






        <aside className="assets-sidebar">
          <div className="sidebar-group">
            <div className="group-label">ASSOCIATED ASSETS</div>
            <div className="asset-quick-adds">
              <button type="button" className="quick-add-btn" onClick={() => addSubContent('link')}>
                <LinkIcon size={14} /> Add Link
              </button>
              <button type="button" className="quick-add-btn" onClick={() => addSubContent('text')}>
                <FileText size={14} /> Add Note
              </button>
            </div>

            <div className="assets-list">
              {formData.subContent.map((item) => (
                <div key={item.id} className="asset-card-luxe">
                  <div className="asset-card-header">
                    <span className="asset-type">{item.type}</span>
                    <button type="button" className="asset-remove" onClick={() => removeSubContent(item.id)}>
                      <X size={14} />
                    </button>
                  </div>
                  <input
                    type="text"
                    placeholder={`Entry ${item.type} details...`}
                    className="asset-input-luxe"
                    value={item.title}
                    onChange={(e) => updateSubContent(item.id, 'title', e.target.value)}
                    required
                  />
                </div>
              ))}
              {formData.subContent.length === 0 && (
                <div className="assets-empty">
                  No assets attached.
                </div>
              )}
            </div>
          </div>

          <div className="sidebar-group info">
            <div className="group-label">WORKFLOW INFO</div>
            <div className="workflow-hint">
              Submitting now will push this item directly into the active review pipeline.
            </div>
          </div>
        </aside>
      </div>
    </div>
  );
};

export default CreateContent;
