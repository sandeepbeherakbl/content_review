import React from 'react';
import { Calendar, User, ArrowRight, MessageSquare } from 'lucide-react';
import Badge from '../ui/Badge';
import './ContentCard.css';

const ContentCard = ({ content, onClick }) => {
  const getStatusLabel = (status) => {
    return status.replace(/_/g, ' ');
  };

  const getBadgeStatus = (status) => {
    if (status === 'approved') return 'approved';
    if (status === 'rejected') return 'rejected';
    if (status.startsWith('pending')) return 'pending';
    return 'draft';
  };

  const formattedDate = new Date(content.createdAt).toLocaleDateString('en-US', {
    month: 'short',
    day: 'numeric',
    year: 'numeric'
  });

  return (
    <div className="content-card glass-gold" onClick={() => onClick(content)}>
      <div className="card-header">
        <Badge status={getBadgeStatus(content.status)}>
          {getStatusLabel(content.status)}
        </Badge>
        <span className="card-id">#{content.id.padStart(3, '0')}</span>
      </div>

      <div className="card-body">
        <h3 className="card-title">{content.title}</h3>
        <p className="card-desc">{content.description}</p>
      </div>

      <div className="card-footer">
        <div className="card-meta">
          <div className="meta-item">
            <User size={14} />
            <span>{content.createdBy}</span>
          </div>
          <div className="meta-item">
            <Calendar size={14} />
            <span>{formattedDate}</span>
          </div>
        </div>
        
        {content.rejectionComment && (
          <div className="card-alert">
            <MessageSquare size={14} />
            <span>Comment</span>
          </div>
        )}

        <div className="card-action">
          <ArrowRight size={18} className="arrow-icon" />
        </div>
      </div>
    </div>
  );
};

export default ContentCard;
