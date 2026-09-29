import React from 'react'
import { BrowserRouter, Routes, Route, NavLink, Navigate, useNavigate } from 'react-router-dom'
import { LogOut, SlidersHorizontal } from 'lucide-react'
import Login from './components/Login'
import Preferences from './components/Preferences'
import ProtectedRoute from './components/ProtectedRoute'
import { AuthProvider, useAuth } from './auth/AuthContext'
import { ModulesProvider, useModules } from './auth/ModulesContext'
import { MODULE_SCREENS, PREFERENCES_PATH, homePath, knownModules } from './modules'

const navClass = ({ isActive }) => (isActive ? 'nav-item active' : 'nav-item')

function Sidebar({ modules }) {
  const navigate = useNavigate()
  const { user, logout } = useAuth()
  const username = user?.username

  const handleLogout = async () => {
    await logout()
    navigate('/login')
  }

  return (
    <aside className="sidebar">
      <div className="sidebar-header">Vigie Platform</div>
      <nav className="sidebar-nav">
        {modules.map((module) => {
          const { path, icon: Icon } = MODULE_SCREENS[module.key]
          return (
            <NavLink key={module.key} to={path} className={navClass}>
              <Icon size={20} />
              {module.label}
            </NavLink>
          )
        })}
      </nav>
      <div style={{ marginTop: 'auto', padding: '1rem', borderTop: '1px solid var(--border)' }}>
        {username && (
          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
            Signed in as <strong style={{ color: 'var(--text-main)' }}>{username}</strong>
          </div>
        )}
        <NavLink to={PREFERENCES_PATH} className={navClass}>
          <SlidersHorizontal size={20} />
          Preferences
        </NavLink>
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

// Routes exist only for the modules the API grants: a hidden module stays
// reachable by its address, a module the role lacks leads back home.
function Shell() {
  const { modules, loading, error, refresh } = useModules()

  if (loading) {
    return <div className="loading">Loading your workspace...</div>
  }
  if (error) {
    return (
      <div className="main-content">
        <div className="error-message">Could not load your modules: {error}</div>
        <button type="button" className="button" onClick={refresh} style={{ marginTop: '1rem' }}>
          Retry
        </button>
      </div>
    )
  }

  const granted = knownModules(modules)
  const home = homePath(modules)

  return (
    <div className="app-container">
      <Sidebar modules={granted.filter((module) => !module.hidden)} />
      <main className="main-content">
        <Routes>
          {granted.map((module) => {
            const { path, Component } = MODULE_SCREENS[module.key]
            return <Route key={module.key} path={path} element={<Component />} />
          })}
          <Route path={PREFERENCES_PATH} element={<Preferences />} />
          <Route path="*" element={<Navigate to={home} replace />} />
        </Routes>
      </main>
    </div>
  )
}

function AuthenticatedLayout() {
  return (
    <ProtectedRoute>
      <ModulesProvider>
        <Shell />
      </ModulesProvider>
    </ProtectedRoute>
  )
}

function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/*" element={<AuthenticatedLayout />} />
        </Routes>
      </AuthProvider>
    </BrowserRouter>
  )
}

export default App
