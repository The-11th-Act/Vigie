import React, { useState, useEffect } from 'react';
import axios from 'axios';

export default function AssetsList() {
  const [data, setData] = useState({ total: 0, items: [] });
  const [page, setPage] = useState(0);

  useEffect(() => {
    axios.get(`/api/v1/assets/?skip=${page * 100}&limit=100`)
      .then(res => setData(res.data))
      .catch(console.error);
  }, [page]);

  return (
    <div>
      <h1>Assets Inventory ({data.total})</h1>
      <div className="glass-panel data-table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>IP Address</th>
              <th>Hostname</th>
              <th>Operating System</th>
              <th>Criticality</th>
            </tr>
          </thead>
          <tbody>
            {data.items.map(asset => (
              <tr key={asset.id}>
                <td>{asset.id}</td>
                <td>{asset.ip_address}</td>
                <td>{asset.hostname || '-'}</td>
                <td>{asset.operating_system || '-'}</td>
                <td>
                  <span className={`badge badge-${asset.business_criticality.toLowerCase()}`}>
                    {asset.business_criticality}
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
