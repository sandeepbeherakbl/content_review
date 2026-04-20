import React, { useState, useEffect } from 'react';
import { Users as UsersIcon, Shield, Mail, Calendar } from 'lucide-react';
import api from '../services/api';
import './Dashboard.css';

const UsersPage = () => {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchUsers = async () => {
      try {
        const data = await api.get('/users');
        setUsers(data);
      } catch (error) {
        console.error('Failed to fetch users:', error);
      } finally {
        setLoading(false);
      }
    };
    fetchUsers();
  }, []);

  return (
    <div className="content-list-page animate-in" style={{ padding: '0 40px' }}>
      <div className="page-header" style={{ marginBottom: '32px' }}>
        <h1 style={{ fontSize: '24px', fontWeight: 700, marginBottom: '8px' }}>Identity & Access</h1>
        <p style={{ color: 'var(--muted)', fontSize: '14px' }}>Manage organizational roles and platform permissions.</p>
      </div>

      <div className="card full-width">
        <div className="table-wrap">
          <table className="main-table">
            <thead>
              <tr>
                <th>Identity</th>
                <th>Role</th>
                <th>Email Address</th>
                <th>Joined</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan="4" style={{ textAlign: 'center', padding: '40px' }}>Loading identities...</td></tr>
              ) : users.map((user) => (
                <tr key={user.id}>
                  <td className="td-title">
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                      <div style={{ width: '32px', height: '32px', borderRadius: '50%', background: 'var(--surface-2)', display: 'flex', alignItems: 'center', justifyCenter: 'center', fontSize: '12px', fontWeight: 600 }}>
                        {user.username.charAt(0).toUpperCase()}
                      </div>
                      {user.username}
                    </div>
                  </td>
                  <td>
                    <span className={`badge badge-${user.role === 'admin' ? 'approved' : user.role === 'reviewer' ? 'pending' : 'draft'}`}>
                      {user.role}
                    </span>
                  </td>
                  <td className="td-meta" style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                    <Mail size={12} /> {user.email || 'n/a'}
                  </td>
                  <td className="td-meta">
                    <Calendar size={12} style={{ marginRight: '6px' }} />
                    {new Date().toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default UsersPage;
