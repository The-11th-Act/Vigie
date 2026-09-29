import {
  Database,
  LayoutGrid,
  LayoutDashboard,
  ListOrdered,
  Server,
  Settings,
  ShieldAlert,
  UploadCloud,
  Wrench,
} from 'lucide-react';
import Dashboard from './components/Dashboard';
import FindingsBacklog from './components/FindingsBacklog';
import RemediationPlan from './components/RemediationPlan';
import AssetsList from './components/AssetsList';
import VulnerabilitiesList from './components/VulnerabilitiesList';
import ScanUpload from './components/ScanUpload';
import AdminPanel from './components/AdminPanel';
import Extracts from './components/Extracts';
import Categorization from './components/Categorization';

// Where each module the API knows (app/core/modules.py) lives in the app.
// A key the API sends but this table lacks is ignored: a newer server never
// breaks an older page.
export const MODULE_SCREENS = {
  dashboard: { path: '/dashboard', icon: LayoutDashboard, Component: Dashboard },
  backlog: { path: '/findings', icon: ListOrdered, Component: FindingsBacklog },
  remediation: { path: '/remediation', icon: Wrench, Component: RemediationPlan },
  categorization: { path: '/categorization', icon: LayoutGrid, Component: Categorization },
  assets: { path: '/assets', icon: Server, Component: AssetsList },
  vulnerabilities: { path: '/vulnerabilities', icon: ShieldAlert, Component: VulnerabilitiesList },
  scans: { path: '/scans', icon: UploadCloud, Component: ScanUpload },
  extracts: { path: '/extracts', icon: Database, Component: Extracts },
  admin: { path: '/admin', icon: Settings, Component: AdminPanel },
};

export const PREFERENCES_PATH = '/preferences';

export function knownModules(modules) {
  return modules.filter((module) => MODULE_SCREENS[module.key]);
}

// Where "/" leads: the first module in the sidebar, else the first granted
// one (all hidden), else the preferences screen (nothing granted).
export function homePath(modules) {
  const known = knownModules(modules);
  const first = known.find((module) => !module.hidden) || known[0];
  return first ? MODULE_SCREENS[first.key].path : PREFERENCES_PATH;
}
