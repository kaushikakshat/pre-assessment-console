import { Navigate, Route, Routes } from 'react-router-dom';
import { RequireAdmin, RequireAuth, landingFor, useAuth } from './auth/AuthContext';
import { Shell } from './pages/Shell';
import { SignIn } from './pages/SignIn';
import { ChangePassword } from './pages/ChangePassword';
import { Help } from './pages/Help';
import { AdminOverview } from './pages/admin/Overview';
import { Users } from './pages/admin/Users';
import { AdminJobs } from './pages/admin/AdminJobs';
import { CapacityPage } from './pages/admin/Capacity';
import { Profiles } from './pages/admin/Profiles';
import { Policies } from './pages/admin/Policies';
import { PolicyVersions } from './pages/admin/PolicyVersions';
import { Audit } from './pages/admin/Audit';
import { Dashboard } from './pages/Dashboard';
import { Assessments } from './pages/Assessments';
import { Wizard } from './pages/Wizard';
import { AssessmentDetail } from './pages/AssessmentDetail';
import { ReportView } from './pages/ReportView';
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
          <Route path="reports/:reportId" element={<ReportView />} />
          <Route path="queue" element={<Queue />} />
          <Route path="account/password" element={<ChangePassword />} />
          <Route path="help" element={<Help />} />
          <Route path="admin" element={<RequireAdmin />}>
            <Route index element={<AdminOverview />} />
            <Route path="users" element={<Users />} />
            <Route path="jobs" element={<AdminJobs />} />
            <Route path="capacity" element={<CapacityPage />} />
            <Route path="profiles" element={<Profiles />} />
            <Route path="policies" element={<Policies />} />
            <Route path="policies/versions" element={<PolicyVersions />} />
            <Route path="audit" element={<Audit />} />
          </Route>
          <Route path="*" element={<section className="card"><EmptyState title="Page not found">Use the navigation to find what you need.</EmptyState></section>} />
        </Route>
      </Route>
    </Routes>
  );
}
