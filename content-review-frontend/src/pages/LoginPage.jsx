import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useNavigate } from 'react-router-dom';
import { User, Lock, XCircle, Eye, EyeOff } from 'lucide-react';
import './LoginPage.css';

const LoginPage = () => {
  const [username, setUsername] = useState('creator1');
  const [password, setPassword] = useState('123456');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState('');
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleLogin = async () => {
    setError('');
    const result = await login(username, password);
    if (result.success) {
      navigate('/dashboard');
    } else {
      setError(result.message);
    }
  };

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-header">
          <div className="login-logo">ContentFlow</div>
          <div className="login-tagline">Review & Approval System</div>
        </div>
        
        <div className="login-body">
          <h1 className="login-title">Sign In</h1>
          <p className="login-subtitle">Enter your credentials to access the workspace.</p>
          
          {error && (
            <div className="error-msg">
              <XCircle size={14} />
              {error}
            </div>
          )}
          
          <div className="form-group">
            <label className="form-label">Username</label>
            <div className="input-with-icon">
              <User size={16} className="input-icon" />
              <input 
                className="login-input" 
                type="text"
                placeholder="Enter your username"
                value={username} 
                onChange={(e) => setUsername(e.target.value)}
              />
            </div>
          </div>

          <div className="form-group">
            <label className="form-label">Password</label>
            <div className="input-with-icon">
              <Lock size={16} className="input-icon" />
              <input 
                className="login-input" 
                type={showPassword ? "text" : "password"}
                placeholder="••••••••"
                value={password} 
                onChange={(e) => setPassword(e.target.value)}
              />
              <button 
                type="button"
                className="password-toggle"
                onClick={() => setShowPassword(!showPassword)}
                aria-label={showPassword ? "Hide password" : "Show password"}
              >
                {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>
          
          <button className="login-btn" onClick={handleLogin}>
            Sign In
          </button>
        </div>
        
        <div className="login-footer">
          &copy; 2026 ContentFlow Systems
        </div>
      </div>
    </div>
  );
};

export default LoginPage;
