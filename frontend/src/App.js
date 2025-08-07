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

  useEffect(() => {
    const csvData = `
    SCORE;CVE;CWE;FIRST_INTRODUCED;PROJECT_NAME;PROJECT_URL;PRODUCT_NAME;ORG_DISPLAY_NAME;ISSUE_SEVERITY;EXPLOIT_MATURITY;COMPUTED_FIXABILITY;ISSUE_URL;ISSUE_TYPE
    103;"[""CVE-2007-5686""]";"[""CWE-264""]";2024-10-25 17:14:34.017;iuriikogan-snyk/nodejs-goof:linux-arm64;https://app.snyk.io/org/cbir-techops/project/556f84a6-0075-41cf-a7a1-a76d87a99b9a;Snyk Container;CBIR - TechOps;Low;No Known Exploit;No Fix Supported;https://app.snyk.io/org/cbir-techops/project/556f84a6-0075-41cf-a7a1-a76d87a99b9a#issue-SNYK-DEBIAN12-SHADOW-1559391;Vulnerability
    125;"[""CVE-2019-9192""]";"[""CWE-674""]";2024-10-25 17:14:34.017;iuriikogan-snyk/nodejs-goof:linux-arm64;https://app.snyk.io/org/cbir-techops/project/556f84a6-0075-41cf-a7a1-a76d87a99b9a;Snyk Container;CBIR - TechOps;Low;No Known Exploit;No Fix Supported;https://app.snyk.io/org/cbir-techops/project/556f84a6-0075-41cf-a7a1-a76d87a99b9a#issue-SNYK-DEBIAN12-GLIBC-1547069;Vulnerability
    `;

    const processData = (csv) => {
      const lines = csv.trim().split('\n');
      const header = lines[0].split(';');
      const records = lines.slice(1).map(line => line.split(';'));

      const issuesBySeverity = {};
      const issuesByEnvironment = {};
      let fixableCriticalIssues = 0;
      const projectIssues = {};

      const severityIndex = header.indexOf('ISSUE_SEVERITY');
      const fixabilityIndex = header.indexOf('COMPUTED_FIXABILITY');
      const projectNameIndex = header.indexOf('PROJECT_NAME');

      records.forEach(record => {
        const severity = record[severityIndex];
        const fixability = record[fixabilityIndex];
        const projectName = record[projectNameIndex];

        if (severity) {
          issuesBySeverity[severity] = (issuesBySeverity[severity] || 0) + 1;
        }

        if (projectName) {
          if (!projectIssues[projectName]) {
            projectIssues[projectName] = { name: projectName, criticalIssueCount: 0, highIssueCount: 0 };
          }
          if (severity === 'Critical') {
            projectIssues[projectName].criticalIssueCount++;
          }
          if (severity === 'High') {
            projectIssues[projectName].highIssueCount++;
          }
        }

        if (severity === 'Critical' && fixability === 'Fixable') {
          fixableCriticalIssues++;
        }
      });

      const top5RiskiestProjects = Object.values(projectIssues)
        .sort((a, b) => b.criticalIssueCount - a.criticalIssueCount || b.highIssueCount - a.highIssueCount)
        .slice(0, 5);

      setData({
        issuesBySeverity,
        issuesByEnvironment: { Production: 10, Staging: 5, Development: 20 }, // Example data
        fixableCriticalIssues,
        top5RiskiestProjects,
      });
    };

    processData(csvData);
  }, []);

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
          <p>Loading and processing Snyk data...</p>
        )}
      </main>
    </div>
  );
}

export default App;

