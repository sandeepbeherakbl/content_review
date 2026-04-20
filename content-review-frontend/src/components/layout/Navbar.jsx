import React from 'react';
import { Layers, Bell, User, Moon, Sun } from 'lucide-react';
import Button from '../ui/Button';
import './Navbar.css';

const Navbar = ({ role, setRole, theme, toggleTheme }) => {
  return (
    <nav className="navbar glass">
      <div className="container nav-content">
        <div className="logo">
          <Layers className="logo-icon" size={24} />
          <span className="logo-text text-gold">ELITE<span className="logo-subtext">FLOW</span></span>
        </div>

        <div className="nav-actions">
          <div className="role-selector glass">
            <span className="role-label">Mode:</span>
            <select 
              value={role} 
              onChange={(e) => setRole(e.target.value)}
              className="role-select"
            >
              <option value="creator">Creator</option>
              <option value="reviewer_1">Reviewer 1</option>
              <option value="reviewer_2">Reviewer 2</option>
              <option value="admin">Admin</option>
            </select>
          </div>

          <button className="theme-toggle" onClick={toggleTheme}>
            {theme === 'dark' ? <Sun size={20} /> : <Moon size={20} />}
          </button>
          
          <button className="nav-icon-btn">
            <Bell size={20} />
          </button>
          
          <div className="user-profile glass">
            <User size={18} />
            <span className="user-name">Sandeep</span>
          </div>
        </div>
      </div>
    </nav>
  );
};

export default Navbar;
