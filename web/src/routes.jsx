import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
import Layout from './components/Layout';
import Dashboard from './components/Dashboard';
import Agents from './components/Agents';
import Hunt from './components/Hunt';
import CasesDashboard from './components/CasesDashboard';

function AppRoutes() {
  return (
    <Router>
      <Layout>
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/agents" element={<Agents />} />
          <Route path="/hunt" element={<Hunt />} />
          <Route path="/cases" element={<CasesDashboard />} />
        </Routes>
      </Layout>
    </Router>
  );
}

export default AppRoutes; 