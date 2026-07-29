import React from 'react'
import { BrowserRouter, Routes, Route, NavLink, useNavigate } from 'react-router-dom'
import { LayoutDashboard, Server, ShieldAlert, UploadCloud, ListOrdered, LogOut } from 'lucide-react'
import Dashboard from './components/Dashboard'
import AssetsList from './components/AssetsList'
import VulnerabilitiesList from './components/VulnerabilitiesList'
import FindingsBacklog from './components/FindingsBacklog'
import ScanUpload from './components/ScanUpload'
import Login from './components/Login'
import ProtectedRoute from './components/ProtectedRoute'

function Sidebar() {
  const navigate = useNavigate()
  const username = localStorage.getItem('username')

  const handleLogout = () => {
    localStorage.removeItem('access_token')
    localStorage.removeItem('role')
    localStorage.removeItem('username')
    navigate('/login')
  }

  return (
    <aside className="sidebar">
      <div className="sidebar-header">Vigie Platform</div>
      <nav className="sidebar-nav">
        <NavLink to="/" end className={({isActive}) => isActive ? "nav-item active" : "nav-item"}>
          <LayoutDashboard size={20} />
          Dashboard
        </NavLink>
        <NavLink to="/assets" className={({isActive}) => isActive ? "nav-item active" : "nav-item"}>
          <Server size={20} />
          Assets
        </NavLink>
        <NavLink to="/vulnerabilities" className={({isActive}) => isActive ? "nav-item active" : "nav-item"}>
          <ShieldAlert size={20} />
          Vulnerabilities
        </NavLink>
        <NavLink to="/findings" className={({isActive}) => isActive ? "nav-item active" : "nav-item"}>
          <ListOrdered size={20} />
          Risk Backlog
        </NavLink>
        <NavLink to="/scans" className={({isActive}) => isActive ? "nav-item active" : "nav-item"}>
          <UploadCloud size={20} />
          Scan Upload
        </NavLink>
      </nav>
      <div style={{ marginTop: 'auto', padding: '1rem', borderTop: '1px solid var(--border)' }}>
        {username && (
          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
            Signed in as <strong style={{ color: 'var(--text-main)' }}>{username}</strong>
          </div>
        )}
        <button
          onClick={handleLogout}
          className="nav-item"
          style={{ background: 'none', border: 'none', width: '100%', cursor: 'pointer', fontSize: 'inherit', fontFamily: 'inherit' }}
        >
          <LogOut size={20} />
          Log out
        </button>
      </div>
    </aside>
  )
}

function AuthenticatedLayout() {
  return (
    <ProtectedRoute>
      <div className="app-container">
        <Sidebar />
        <main className="main-content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/assets" element={<AssetsList />} />
            <Route path="/vulnerabilities" element={<VulnerabilitiesList />} />
            <Route path="/findings" element={<FindingsBacklog />} />
            <Route path="/scans" element={<ScanUpload />} />
          </Routes>
        </main>
      </div>
    </ProtectedRoute>
  )
}

function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/*" element={<AuthenticatedLayout />} />
      </Routes>
    </BrowserRouter>
  )
}

export default App
