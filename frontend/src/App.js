import React, { useState, useEffect } from 'react';
import Papa from 'papaparse';
import { PieChart } from 'react-minimal-pie-chart';
import './App.css';

// Helper function to process data from CSV or API
const processData = (records) => {
  const issuesBySeverity = {};
  const issuesByEnvironment = {};
  const issuesByProject = {};
  let fixableCriticals = 0;

  records.forEach(record => {
    const severity = record.ISSUE_SEVERITY || record.severity;
    const autofixable = record.COMPUTED_FIXABILITY || record.fixability;
    const projectName = record.PROJECT_NAME || record.projectName;
    const environments = record.PROJECT_ENVIRONMENTS || record.environments || 'N/A';

    if (severity) issuesBySeverity[severity] = (issuesBySeverity[severity] || 0) + 1;
    if (projectName) issuesByProject[projectName] = (issuesByProject[projectName] || 0) + 1;
    
    const envs = environments.split(',').map(e => e.trim()).filter(e => e);
    if (envs.length > 0) {
        envs.forEach(env => issuesByEnvironment[env] = (issuesByEnvironment[env] || 0) + 1);
    } else {
        issuesByEnvironment['N/A'] = (issuesByEnvironment['N/A'] || 0) + 1;
    }

    if (severity === 'critical' && autofixable === 'fixable') {
      fixableCriticals++;
    }
  });

  return { issuesBySeverity, issuesByEnvironment, issuesByProject, fixableCriticals };
};

const BarChart = ({ data, title }) => (
  <div className="chart-container">
    <h3>{title}</h3>
    <div className="bar-chart">
      {Object.entries(data).map(([key, value]) => (
        <div key={key} className="bar-item">
          <div className="bar-label">{key}</div>
          <div className="bar" style={{ width: `${(value / Math.max(...Object.values(data))) * 100}%` }}>
            {value}
          </div>
        </div>
      ))}
    </div>
  </div>
);

const PieChartComponent = ({ data, title }) => {
  const chartData = Object.entries(data).map(([title, value], i) => ({
    title,
    value,
    color: ['#0E00B9', '#4D82F3', '#8C6DFF', '#19C3A3', '#f57c00'][i % 5],
  }));

  return (
    <div className="chart-container pie">
      <h3>{title}</h3>
      <PieChart data={chartData} lineWidth={60} paddingAngle={2}
        label={({ dataEntry }) => `${dataEntry.title}: ${dataEntry.value}`}
        labelStyle={{ fontSize: '6px', fill: '#fff' }}
      />
    </div>
  );
};

const HighImpactVulnerabilities = ({ data }) => (
  <div className="card kpi">
    <h2>{data}</h2>
    <p>High-Impact Vulnerabilities</p>
  </div>
);

const StatusBar = ({ status }) => (
  <div className="status-bar">
    <p>{status}</p>
  </div>
);

function App() {
  const [data, setData] = useState(null);
  const [status, setStatus] = useState('Loading initial data...');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    // 1. Load static data first
    Papa.parse('/snyk_export.csv', {
      download: true,
      header: true,
      skipEmptyLines: true,
      complete: (results) => {
        const processed = processData(results.data);
        setData(processed);
        setStatus('Static data loaded. Fetching live data...');

        // 2. Then fetch live data
        fetch('/api/data')
          .then(response => {
            if (!response.ok) throw new Error('Failed to fetch live data');
            return response.json();
          })
          .then(liveData => {
            // The backend already processes the data, so we can use it directly
            setData(liveData);
            setStatus('Dashboard is up to date.');
          })
          .catch(error => {
            console.error('Error fetching live data:', error);
            setStatus('Failed to load live data. Displaying static data.');
          });
      },
      error: (err) => {
        console.error('Failed to load static CSV:', err);
        setStatus('Error loading initial data. Trying to fetch live data...');
        // Attempt to fetch live data even if static fails
        fetch('/api/data')
          .then(response => response.json())
          .then(liveData => {
            setData(liveData);
            setStatus('Dashboard is up to date.');
          })
          .catch(fetchErr => setStatus('Failed to load any data.'));
      },
    });
  }, []);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await fetch('/api/data');
        if (!response.ok) {
          const errorText = await response.text();
          throw new Error(`Network response was not ok: ${errorText}`);
        }
        const result = await response.json();
        setData(result);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
  }, []);

  if (loading) {
    return <div className="App"><p>Loading and processing Snyk data...</p></div>;
  }

  if (error) {
    return <div className="App"><p className="error">Error: {error}</p></div>;
  }

  return (
    <div className="App">
      <header className="App-header">
        <h1>Snyk Export API Dash</h1>
      </header>
      <StatusBar status={status} />
      <main className="dashboard">
        {data ? (
          <>
            <div className="kpi-row">
              <div className="card kpi">
                <h2>{data.fixableCriticalIssues}</h2>
                <p>Fixable Critical Issues</p>
              </div>
              <HighImpactVulnerabilities data={data.highImpactVulnerabilities} />
            </div>
            <div className="chart-row">
              {data.issuesBySeverity && <BarChart data={data.issuesBySeverity} title="Issues by Severity" />}
              {data.issuesByEnvironment && <PieChartComponent data={data.issuesByEnvironment} title="Issues by Environment" />}
              {data.issuesByType && <PieChartComponent data={data.issuesByType} title="Issues by Type" />}
              {data.vulnerabilityAge && <BarChart data={data.vulnerabilityAge} title="Vulnerability Age" />}
              {data.fixability && <PieChartComponent data={data.fixability} title="Fixability Status" />}
            </div>
            <div className="list-container">
              <h3>Top 5 Riskiest Projects</h3>
              <ul>
                {data.top5RiskiestProjects.map(proj => (
                  <li key={proj.name}>
                    <span>{proj.name}</span>
                    <span className="project-issues">
                      <span className="critical-count">{proj.criticalIssueCount} Critical</span>
                      <span className="high-count">{proj.highIssueCount} High</span>
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          </>
        ) : (
          <p>Loading dashboard...</p>
        )}
      </main>
    </div>
  );
}

export default App;
