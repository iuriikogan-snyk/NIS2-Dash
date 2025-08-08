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

const processData = (csv) => {

  const lines = csv.trim().split('\n').filter(line => line.trim() !== '');
  if (lines.length < 2) return {};
  // Find the header line (should be the first line with 'ISSUE_SEVERITY' etc)
  let headerLineIdx = 0;
  while (headerLineIdx < lines.length && !lines[headerLineIdx].includes('ISSUE_SEVERITY')) {
    headerLineIdx++;
  }
  if (headerLineIdx >= lines.length) return {};
  const header = lines[headerLineIdx].split(';');
  const records = lines.slice(headerLineIdx + 1).map(line => line.split(';'));

  const issuesBySeverity = {};
  const issuesByEnvironment = {};
  let fixableCriticalIssues = 0;
  const projectIssues = {};
  const issuesByType = {};
  const vulnerabilityAge = { "<30": 0, "30-60": 0, "61-90": 0, ">90": 0 };
  const fixability = { Fixable: 0, "No Fix": 0, "Partially Fixable": 0 };

  const severityIndex = header.indexOf('ISSUE_SEVERITY');
  const fixabilityIndex = header.indexOf('COMPUTED_FIXABILITY');
  const projectNameIndex = header.indexOf('PROJECT_NAME');
  const issueTypeIndex = header.indexOf('ISSUE_TYPE');
  const firstIntroducedIndex = header.indexOf('FIRST_INTRODUCED');
  const exploitMaturityIndex = header.indexOf('EXPLOIT_MATURITY');

  let highImpactVulnerabilities = 0;

  records.forEach(record => {
    // skip if record is not the right length
    if (record.length < header.length) return;
    const severity = record[severityIndex];
    const fixabilityStatus = record[fixabilityIndex];
    const projectName = record[projectNameIndex];
    const issueType = record[issueTypeIndex];
    const firstIntroduced = record[firstIntroducedIndex];
    const exploitMaturity = record[exploitMaturityIndex];

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

    if (severity === 'Critical' && fixabilityStatus === 'Fixable') {
      fixableCriticalIssues++;
    }

    if ((severity === 'Critical' || severity === 'High') && exploitMaturity !== 'No Known Exploit') {
      highImpactVulnerabilities++;
    }

    if (issueType) {
      issuesByType[issueType] = (issuesByType[issueType] || 0) + 1;
    }

    if (firstIntroduced) {
      const days = Math.floor((new Date() - new Date(firstIntroduced)) / (1000 * 60 * 60 * 24));
      if (days < 30) vulnerabilityAge["<30"]++;
      else if (days <= 60) vulnerabilityAge["30-60"]++;
      else if (days <= 90) vulnerabilityAge["61-90"]++;
      else vulnerabilityAge[">90"]++;
    }

    if (fixabilityStatus) {
      if (fixabilityStatus === 'Fixable') fixability.Fixable++;
      else if (fixabilityStatus === 'No Fix Supported') fixability["No Fix"]++;
      else if (fixabilityStatus === 'Partially Fixable') fixability["Partially Fixable"]++;
    }
  });

  const top5RiskiestProjects = Object.values(projectIssues)
    .sort((a, b) => b.criticalIssueCount - a.criticalIssueCount || b.highIssueCount - a.highIssueCount)
    .slice(0, 5);

  return {
    issuesBySeverity,
    issuesByEnvironment: { Production: 10, Staging: 5, Development: 20 }, // Example data
    fixableCriticalIssues,
    top5RiskiestProjects,
    issuesByType,
    vulnerabilityAge,
    fixability,
    highImpactVulnerabilities,
  };
};

function App() {
  const [data, setData] = useState(null);

  useEffect(() => {
    fetch('/snyk_export.csv')
      .then(response => response.text())
      .then(csvData => {
        setData(processData(csvData));
      });
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
          <p>Loading and processing Snyk data...</p>
        )}
      </main>
    </div>
  );
}

export default App;

