import React from 'react';
import './Button.css';

const Button = ({ children, variant = 'primary', size = 'md', className = '', ...props }) => {
  return (
    <button 
      className={`btn btn-${variant} btn-${size} ${className}`} 
      {...props}
    >
      <span className="btn-content">{children}</span>
    </button>
  );
};

export default Button;
