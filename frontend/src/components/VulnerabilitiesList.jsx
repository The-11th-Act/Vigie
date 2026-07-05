import React, { useState, useEffect } from 'react';
import axios from 'axios';

export default function VulnerabilitiesList() {
  const [data, setData] = useState({ total: 0, items: [] });
  const [page, setPage] = useState(0);

  useEffect(() => {
    axios.get(`/api/v1/vulnerabilities/?skip=${page * 100}&limit=100`)
      .then(res => setData(res.data))
      .catch(console.error);
  }, [page]);

  return (
    <div>
      <h1>Vulnerability Database ({data.total})</h1>
      <div className="glass-panel data-table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>CVE ID</th>
              <th>Title</th>
              <th>CVSS</th>
              <th>Severity</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map(vuln => (
              <tr key={vuln.id}>
                <td style={{fontWeight: 600, color: 'var(--accent)'}}>{vuln.cve_id}</td>
                <td style={{maxWidth: '400px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis'}}>
                  {vuln.title}
                </td>
                <td>{vuln.cvss_score.toFixed(1)}</td>
                <td>
                  <span className={`badge badge-${vuln.severity.toLowerCase()}`}>
                    {vuln.severity}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
