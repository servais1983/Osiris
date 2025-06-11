import { createBrowserRouter } from 'react-router-dom';
import Dashboard from './components/Dashboard';
import Agents from './components/Agents';
import Hunt from './components/Hunt';
import Timeline from './components/Timeline';
import Cases from './components/Cases';
import Layout from './components/Layout';

export const router = createBrowserRouter([
  {
    path: '/',
    element: <Layout />,
    children: [
      {
        index: true,
        element: <Dashboard />
      },
      {
        path: 'agents',
        element: <Agents />
      },
      {
        path: 'hunt',
        element: <Hunt />
      },
      {
        path: 'timeline/:agentId',
        element: <Timeline />
      },
      {
        path: 'cases',
        element: <Cases />
      }
    ]
  }
]); 