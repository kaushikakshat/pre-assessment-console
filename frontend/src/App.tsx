import { Navigate, Route, Routes } from 'react-router-dom';
import { RequireAdmin, RequireAuth, landingFor, useAuth } from './auth/AuthContext';
import { Shell } from './pages/Shell';
import { SignIn } from './pages/SignIn';
import { Help } from './pages/Help';
import { Stub } from './pages/Stub';
import { Dashboard } from './pages/Dashboard';
import { Assessments } from './pages/Assessments';
import { Wizard } from './pages/Wizard';
import { AssessmentDetail } from './pages/AssessmentDetail';
import { Queue } from './pages/Queue';
import { EmptyState } from './components';

function Home() {
  return <Navigate to={landingFor(useAuth().user!)} replace />;
}

export function App() {
  return (
    <Routes>
      <Route path="/signin" element={<SignIn />} />
      <Route element={<RequireAuth />}>
        <Route element={<Shell />}>
          <Route index element={<Home />} />
          <Route path="dashboard" element={<Dashboard />} />
          <Route path="assessments" element={<Assessments />} />
          <Route path="assessments/new" element={<Wizard />} />
          <Route path="assessments/:id" element={<AssessmentDetail />} />
          <Route path="assessments/:id/scan" element={<Wizard />} />
          <Route path="queue" element={<Queue />} />
          <Route path="help" element={<Help />} />
          <Route path="admin" element={<RequireAdmin />}>
            <Route index element={<Stub title="Admin overview" />} />
            <Route path="users" element={<Stub title="Users & Roles" />} />
            <Route path="jobs" element={<Stub title="Assessments / Jobs" />} />
            <Route path="capacity" element={<Stub title="Scan Capacity & Scheduling" />} />
            <Route path="audit" element={<Stub title="Audit Logs" />} />
          </Route>
          <Route path="*" element={<section className="card"><EmptyState title="Page not found">Use the navigation to find what you need.</EmptyState></section>} />
        </Route>
      </Route>
    </Routes>
  );
}
