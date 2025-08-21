import React, { useState, useEffect } from 'react';
import Papa from 'papaparse';
import { PieChart, Pie, Cell, Tooltip, Legend, BarChart, Bar, XAxis, YAxis, CartesianGrid } from 'recharts';
import './App.css';

const COLORS = { critical: '#9D0208', high: '#D00000', medium: '#FAA307', low: '#036666' };

const App = () => {
    const [data, setData] = useState(null);
    const [status, setStatus] = useState('Loading initial data...');

    useEffect(() => {
        // Preload data from static CSV
        Papa.parse('/snyk_export.csv', {
            download: true,
            header: true,
            skipEmptyLines: true,
            complete: (result) => {
                try {
                    const preloadedData = processData(result.data);
                    setData(preloadedData);
                    setStatus('Initial data loaded. Fetching live data...');
                    fetchLiveSnykData();
                } catch (error) {
                    console.error('Error processing preloaded data:', error);
                    setStatus(`Error processing initial data: ${error.message}`);
                    fetchLiveSnykData(); // Attempt to fetch live data even if preloading fails
                }
            },
            error: (error) => {
                console.error('Error preloading CSV:', error);
                setStatus('Could not load initial data. Fetching live data...');
                fetchLiveSnykData();
            }
        });
    }, []);

    const fetchLiveSnykData = () => {
        fetch('/api/data')
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                return response.json();
            })
            .then(liveData => {
                setData(liveData);
                setStatus('Live data loaded successfully.');
            })
            .catch(error => {
                console.error('Error fetching live data:', error);
                setStatus(`Failed to fetch live data: ${error.message}. Displaying initial data.`);
            });
    };

    const processData = (csvData) => {
        const issuesBySeverity = {};
        let totalScaIssues = 0;
        let totalSastIssues = 0;

        csvData.forEach(row => {
            const severity = row['ISSUE_SEVERITY'];
            if (severity) {
                issuesBySeverity[severity] = (issuesBySeverity[severity] || 0) + 1;
            }
            if (row['ISSUE_TYPE'] === 'sca_open_source') totalScaIssues++;
            if (row['ISSUE_TYPE'] === 'sast') totalSastIssues++;
        });

        return {
            issuesBySeverity,
            totalScaIssues,
            totalSastIssues,
            top5RiskiestProjects: [], // Static processing does not calculate this
        };
    };

    if (!data) {
        return <div className="status-bar">{status}</div>;
    }

    const severityData = Object.entries(data.issuesBySeverity || {}).map(([name, value]) => ({ name, value }));

    return (
        <div className="App">
            <header className="App-header">
                <h1>NIS2 Compliance Dashboard</h1>
                <div className="status-bar">{status}</div>
            </header>
            <main className="dashboard">
                <div className="grid-container">
                    <div className="card large-card">
                        <h2>Top 5 Riskiest Projects</h2>
                        <ProjectTable projects={data.top5RiskiestProjects || []} />
                    </div>
                    <div className="card">
                        <h2>Issues by Severity</h2>
                        <PieChart width={400} height={300}>
                            <Pie data={severityData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={100} fill="#8884d8" label>
                                {severityData.map((entry, index) => (
                                    <Cell key={`cell-${index}`} fill={COLORS[entry.name.toLowerCase()] || '#8884d8'} />
                                ))}
                            </Pie>
                            <Tooltip />
                            <Legend />
                        </PieChart>
                    </div>
                    <div className="card">
                        <h2>Vulnerability Type Overview</h2>
                        <div className="vuln-overview">
                            <div className="vuln-type">
                                <h3>SCA Issues</h3>
                                <p>{data.totalScaIssues}</p>
                            </div>
                            <div className="vuln-type">
                                <h3>SAST Issues</h3>
                                <p>{data.totalSastIssues}</p>
                            </div>
                        </div>
                    </div>
                </div>
            </main>
        </div>
    );
};

const ProjectTable = ({ projects }) => {
    if (projects.length === 0) {
        return <p>No project data available. This may be because live data is still loading or could not be fetched.</p>;
    }

    return (
        <table className="project-table">
            <thead>
                <tr>
                    <th>Project Name</th>
                    <th>Critical</th>
                    <th>High</th>
                    <th>Medium</th>
                    <th>Low</th>
                    <th>SCA</th>
                    <th>SAST</th>
                </tr>
            </thead>
            <tbody>
                {projects.map(proj => (
                    <tr key={proj.id}>
                        <td><a href={proj.url} target="_blank" rel="noopener noreferrer">{proj.name}</a></td>
                        <td className="severity-critical">{proj.criticalIssueCount}</td>
                        <td className="severity-high">{proj.highIssueCount}</td>
                        <td className="severity-medium">{proj.mediumIssueCount}</td>
                        <td className="severity-low">{proj.lowIssueCount}</td>
                        <td>{proj.scaIssueCount}</td>
                        <td>{proj.sastIssueCount}</td>
                    </tr>
                ))}
            </tbody>
        </table>
    );
};

export default App;
