import React, { useState } from 'react';
import { PieChart } from 'react-minimal-pie-chart';
import './App.css';

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
    color: ['#d32f2f', '#f57c00', '#1976d2', '#6c757d', '#28a745'][i % 5],
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

function App() {
  const [data, setData] = useState(null);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [orgs, setOrgs] = useState('');
  const [introducedFrom, setIntroducedFrom] = useState('');
  const [introducedTo, setIntroducedTo] = useState('');
  const [updatedFrom, setUpdatedFrom] = useState('');
  const [updatedTo, setUpdatedTo] = useState('');
  const [environments, setEnvironments] = useState('');
  const [lifecycles, setLifecycles] = useState('');
  const [severities, setSeverities] = useState('');

  const fetchData = () => {
    setLoading(true);
    setError('');
    const params = new URLSearchParams({
      orgs,
      introduced_from: introducedFrom,
      introduced_to: introducedTo,
      updated_from: updatedFrom,
      updated_to: updatedTo,
      env: environments,
      lifecycle: lifecycles,
      severities,
    });

    fetch(`/api/data?${params}`)
      .then(response => {
        if (!response.ok) throw new Error('Network response was not ok');
        return response.json();
      })
      .then(data => setData(data))
      .catch(err => setError('Failed to load data. Ensure the backend is running and parameters are correct.'))
      .finally(() => setLoading(false));
  };

  return (
    <div className="App">
      <header className="App-header">
        <h1>NIS2 Compliance Dashboard</h1>
      </header>
      <main className="dashboard">
        <div className="filter-form">
          <input type="text" value={orgs} onChange={e => setOrgs(e.target.value)} placeholder="Snyk Orgs (comma-separated)" />
          <input type="date" value={introducedFrom} onChange={e => setIntroducedFrom(e.target.value)} />
          <input type="date" value={introducedTo} onChange={e => setIntroducedTo(e.target.value)} />
          <input type="date" value={updatedFrom} onChange={e => setUpdatedFrom(e.target.value)} />
          <input type="date" value={updatedTo} onChange={e => setUpdatedTo(e.target.value)} />
          <input type="text" value={environments} onChange={e => setEnvironments(e.target.value)} placeholder="Environments (comma-separated)" />
          <input type="text" value={lifecycles} onChange={e => setLifecycles(e.target.value)} placeholder="Lifecycles (comma-separated)" />
          <input type="text" value={severities} onChange={e => setSeverities(e.target.value)} placeholder="Severities (comma-separated)" />
          <button onClick={fetchData} disabled={loading}>
            {loading ? 'Loading...' : 'Get Data'}
          </button>
        </div>

        {error && <p className="error">{error}</p>}
        {loading && !error && <p>Loading and processing Snyk data...</p>}

        {data && !loading && (
          <>
            <div className="kpi-row">
              <div className="card kpi">
                <h2>{data.fixableCriticalIssues}</h2>
                <p>Fixable Critical Issues</p>
              </div>
            </div>
            <div className="chart-row">
              {data.issuesBySeverity && <BarChart data={data.issuesBySeverity} title="Issues by Severity" />}
              {data.issuesByEnvironment && <PieChartComponent data={data.issuesByEnvironment} title="Issues by Environment" />}
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
        )}
      </main>
    </div>
  );
}

export default App;
