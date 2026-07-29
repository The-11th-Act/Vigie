import React from 'react';
import { Navigate } from 'react-router-dom';

export default function ProtectedRoute({ children }) {
  if (!localStorage.getItem('access_token')) {
    return <Navigate to="/login" replace />;
  }
  return children;
}
