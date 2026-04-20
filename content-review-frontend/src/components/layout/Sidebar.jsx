import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { LayoutDashboard, FileText, PlusCircle, Clock, CheckCircle, Users, LogOut } from 'lucide-react';
import { useAuth } from '../../context/AuthContext';
import './Sidebar.css';

const Sidebar = () => {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div className="logo">ContentFlow</div>
        <div className="tagline">Review & Approval</div>
      </div>

      <nav className="sidebar-nav">
        <div className="nav-section-label">Main</div>
        <NavLink to="/dashboard" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
          <LayoutDashboard className="nav-icon" size={16} />
          Dashboard
        </NavLink>
        <NavLink to="/content" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
          <FileText className="nav-icon" size={16} />
          All Content
        </NavLink>
        {(user?.role === 'creator' || user?.role === 'admin') && (
          <NavLink to="/create" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
            <PlusCircle className="nav-icon" size={16} />
            New Content
          </NavLink>
        )}

        <div className="nav-section-label">Review</div>
        <NavLink to="/pending" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
          <Clock className="nav-icon" size={16} />
          Pending Review
          <span className="nav-badge"></span>
        </NavLink>
        <NavLink to="/approved" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
          <CheckCircle className="nav-icon" size={16} />
          Approved
        </NavLink>

        {(user?.role === 'admin') && (
          <>
            <div className="nav-section-label">System</div>
            <NavLink to="/users" className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
              <Users className="nav-icon" size={16} />
              Users
            </NavLink>
          </>
        )}
      </nav>

      <div className="sidebar-user">
        <div className="user-switcher-label">AUTHENTICATED AS</div>
        <div className="user-info">
          <div className="user-name">{user?.username}  <div className="user-role-badge">{user?.role}</div> </div>
        </div>
        <button className="logout-btn" onClick={handleLogout}>
          <LogOut size={14} />
          Logout
        </button>
      </div>
    </aside>
  );
};

export default Sidebar;
