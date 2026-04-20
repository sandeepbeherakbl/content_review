import React from 'react';
import './Badge.css';

const Badge = ({ children, status = 'pending', className = '' }) => {
  return (
    <span className={`badge badge-${status} ${className}`}>
      {children}
    </span>
  );
};

export default Badge;
