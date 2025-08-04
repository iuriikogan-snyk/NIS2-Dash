import React, { useState, useEffect } from 'react';
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

  useEffect(() => {
    fetch('/api/data')
      .then(response => {
        if (!response.ok) throw new Error('Network response was not ok');
        return response.json();
      })
      .then(data => setData(data))
      .catch(err => setError('Failed to load data. Ensure the backend is running.'));
  }, []);

  return (
    <div className="App">
      <header className="App-header">
        <h1>NIS2 Compliance Dashboard</h1>
      </header>
      <main className="dashboard">
        {error && <p className="error">{error}</p>}
        {data ? (
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
        ) : (
          !error && <p>Loading and processing Snyk data...</p>
        )}
      </main>
    </div>
  );
}

export default App;