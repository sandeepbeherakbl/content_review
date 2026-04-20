import React from 'react';
import { Outlet, Navigate, useLocation, Link } from 'react-router-dom';
import { Plus } from 'lucide-react';
import Sidebar from './Sidebar';
import { useAuth } from '../../context/AuthContext';
import './MainLayout.css';

const MainLayout = () => {
  const { user } = useAuth();
  const location = useLocation();

  if (!user) {
    return <Navigate to="/login" replace />;
  }

  const getPageTitle = (pathname) => {
    if (pathname === '/dashboard') return 'Dashboard';
    if (pathname === '/content') return 'All Content';
    if (pathname === '/create') return 'New Content';
    if (pathname === '/pending') return 'Pending Review';
    if (pathname === '/approved') return 'Approved Content';
    if (pathname === '/users') return 'User Management';
    if (pathname.startsWith('/content/')) return 'Content Detail';
    return 'Home';
  };

  const pageTitle = getPageTitle(location.pathname);

  return (
    <div className="layout">
      <Sidebar />
      <main className="main-content-wrapped">
        <div className="topbar">
          <div className="topbar-inner">
            <span className="topbar-breadcrumb">ContentFlow / {pageTitle}</span>
            <div className="topbar-actions">
              {(location.pathname === '/content' || location.pathname === '/dashboard') && (user?.role === 'creator' || user?.role === 'admin') && (
                <Link to="/create" className="btn-primary-sm">
                  <Plus size={14} /> New Content
                </Link>
              )}
            </div>
          </div>
        </div>
        <div className="page-overflow-container">
          <div className="container content-inner animate-in">
            <Outlet />
          </div>
        </div>
      </main>
    </div>
  );
};

export default MainLayout;
