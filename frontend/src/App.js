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

function App() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

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
          <p>No data available.</p>
        )}
      </main>
    </div>
  );
}

export default App;
