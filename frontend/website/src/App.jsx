import { useEffect } from "react";
import { BrowserRouter, Routes, Route } from "react-router-dom";
import { ToastProvider } from "./components/Toast";
import Layout from "./components/Layout";
import Landing from "./pages/Landing";
import Dashboard from "./pages/Dashboard";
import Connect from "./pages/Connect";
import Logs from "./pages/Logs";
import WorkflowBuilder from "./workflow/WorkflowBuilder";
import Chatbot from "./pages/Chatbot";
import VisualDemo from "./pages/VisualDemo";
import { fetchBackendHealth } from "./api";
import "./styles/safeo.css";
import "./styles/landing.css";

export default function App() {
  useEffect(() => {
    fetchBackendHealth().catch(() => {});
  }, []);

  return (
    <ToastProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Landing />} />
          <Route
            path="/*"
            element={
              <Layout>
                <Routes>
                  <Route path="/app" element={<Dashboard />} />
                  <Route path="/connect" element={<Connect />} />
                  <Route path="/logs" element={<Logs />} />
                  <Route path="/workflow" element={<WorkflowBuilder />} />
                  <Route path="/chat" element={<Chatbot />} />
                  <Route path="/visual" element={<VisualDemo />} />
                </Routes>
              </Layout>
            }
          />
        </Routes>
      </BrowserRouter>
    </ToastProvider>
  );
}
