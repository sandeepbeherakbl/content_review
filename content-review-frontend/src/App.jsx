import React from 'react';
import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { AuthProvider } from './context/AuthContext';
import MainLayout from './components/layout/MainLayout';
import LoginPage from './pages/LoginPage';
import Dashboard from './pages/Dashboard';
import ContentList from './pages/ContentList';
import CreateContent from './pages/CreateContent';
import ContentDetail from './pages/ContentDetail';
import PendingReview from './pages/PendingReview';
import ApprovedContent from './pages/ApprovedContent';
import UsersPage from './pages/UsersPage';
import EditContent from './pages/EditContent';
import './App.css';

function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          
          <Route element={<MainLayout />}>
            <Route path="/" element={<Navigate to="/dashboard" replace />} />
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/content" element={<ContentList filter="all" />} />
            <Route path="/content/:id" element={<ContentDetail />} />
            <Route path="/edit/:id" element={<EditContent />} />
            <Route path="/create" element={<CreateContent />} />
            <Route path="/pending" element={<PendingReview />} />
            <Route path="/approved" element={<ApprovedContent />} />
            <Route path="/users" element={<UsersPage />} />
          </Route>
          
          <Route path="*" element={<Navigate to="/dashboard" replace />} />
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}

export default App;
