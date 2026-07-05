import React from 'react'
import { BrowserRouter, Routes, Route, NavLink } from 'react-router-dom'
import { LayoutDashboard, Server, ShieldAlert, UploadCloud } from 'lucide-react'
import Dashboard from './components/Dashboard'
import AssetsList from './components/AssetsList'
import VulnerabilitiesList from './components/VulnerabilitiesList'

function Sidebar() {
  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        RBVM Platform
      </div>
      <nav className="sidebar-nav">
        <NavLink to="/" className={({isActive}) => isActive ? "nav-item active" : "nav-item"}>
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
      </nav>
    </aside>
  )
}

function App() {
  return (
    <BrowserRouter>
      <div className="app-container">
        <Sidebar />
        <main className="main-content">
          <Routes>
            <Route path="/" element={<Dashboard />} />
            <Route path="/assets" element={<AssetsList />} />
            <Route path="/vulnerabilities" element={<VulnerabilitiesList />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}

export default App
