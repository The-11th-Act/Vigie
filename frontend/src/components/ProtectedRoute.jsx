import React from 'react';
import { Navigate } from 'react-router-dom';
import { useAuth } from '../auth/AuthContext';

export default function ProtectedRoute({ children }) {
  const { user, loading } = useAuth();

  // The session is an HttpOnly cookie the page cannot inspect: wait for the
  // API to say who is signed in before deciding.
  if (loading) {
    return <div className="loading">Loading session...</div>;
  }
  if (!user) {
    return <Navigate to="/login" replace />;
  }
  return children;
}
