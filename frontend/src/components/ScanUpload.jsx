import React, { useState, useCallback } from 'react';
import { scanService } from '../services';
import ScanHistory from './ScanHistory';
import { UploadCloud, FileText, CheckCircle, Loader, AlertCircle } from 'lucide-react';

const SCAN_TYPES = [
  { value: 'nessus', label: 'Nessus (.nessus XML)' },
  { value: 'openvas', label: 'OpenVAS (XML)' },
];

export default function ScanUpload() {
  const [scanType, setScanType] = useState('nessus');
  const [file, setFile] = useState(null);
  const [uploading, setUploading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);
  const [polling, setPolling] = useState(false);
  const [historyToken, setHistoryToken] = useState(0);

  const handleFileChange = (e) => {
    setFile(e.target.files[0]);
    setResult(null);
    setError(null);
  };

  const pollStatus = useCallback(async (taskId) => {
    setPolling(true);
    let attempts = 0;
    const maxAttempts = 60;

    const interval = setInterval(async () => {
      attempts++;
      try {
        // The endpoint returns the stored ScanJob: its status and counters,
        // not Celery's raw `state` / `result`.
        const res = await scanService.getStatus(taskId);
        const job = res.data;

        if (job.status === 'Success') {
          clearInterval(interval);
          setPolling(false);
          setResult({ state: 'SUCCESS', data: job });
          setHistoryToken((token) => token + 1);
        } else if (job.status === 'Failed') {
          clearInterval(interval);
          setPolling(false);
          setResult({ state: 'FAILURE', data: job });
          setHistoryToken((token) => token + 1);
        } else if (attempts >= maxAttempts) {
          clearInterval(interval);
          setPolling(false);
          setResult({ state: 'TIMEOUT', data: { message: 'Task is taking too long. Check back later.' } });
        }
      } catch {
        clearInterval(interval);
        setPolling(false);
        setError('Failed to check task status');
      }
    }, 2000);
  }, []);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!file) {
      setError('Please select a file');
      return;
    }

    setUploading(true);
    setError(null);
    setResult(null);

    try {
      const res = await scanService.upload(file, scanType);
      setResult({ state: 'PENDING', task_id: res.data.task_id });
      pollStatus(res.data.task_id);
    } catch (err) {
      setError(err.response?.data?.detail || 'Upload failed');
    } finally {
      setUploading(false);
    }
  };

  return (
    <div>
      <h1>Upload Scan Results</h1>

      <div className="glass-panel" style={{maxWidth: 600, padding: '2rem'}}>
        <form onSubmit={handleSubmit}>
          <div style={{marginBottom: '1.5rem'}}>
            <label style={{display: 'block', marginBottom: '0.5rem', color: 'var(--text-muted)', fontSize: '0.875rem'}}>
              Scan Type
            </label>
            <select
              value={scanType}
              onChange={(e) => setScanType(e.target.value)}
              style={{
                width: '100%', padding: '0.6rem 0.75rem',
                background: 'rgba(255,255,255,0.05)', border: '1px solid var(--border)',
                borderRadius: '8px', color: 'var(--text-main)', fontSize: '0.875rem',
                outline: 'none', cursor: 'pointer',
              }}
            >
              {SCAN_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
            </select>
          </div>

          <div style={{marginBottom: '1.5rem'}}>
            <label style={{display: 'block', marginBottom: '0.5rem', color: 'var(--text-muted)', fontSize: '0.875rem'}}>
              Scan File
            </label>
            <div
              onClick={() => document.getElementById('file-input').click()}
              style={{
                border: '2px dashed var(--border)', borderRadius: '10px',
                padding: '2rem', textAlign: 'center', cursor: 'pointer',
                transition: 'border-color 0.2s',
              }}
              onMouseEnter={(e) => e.currentTarget.style.borderColor = 'var(--accent)'}
              onMouseLeave={(e) => e.currentTarget.style.borderColor = 'var(--border)'}
            >
              <input id="file-input" type="file" accept=".xml,.nessus" onChange={handleFileChange} style={{display: 'none'}} />
              {file ? (
                <div style={{display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '0.5rem'}}>
                  <FileText size={20} style={{color: 'var(--accent)'}} />
                  <span style={{color: 'var(--text-main)'}}>{file.name}</span>
                  <span style={{color: 'var(--text-muted)', fontSize: '0.75rem'}}>({(file.size / 1024).toFixed(1)} KB)</span>
                </div>
              ) : (
                <div style={{display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.5rem'}}>
                  <UploadCloud size={28} style={{color: 'var(--text-muted)'}} />
                  <span style={{color: 'var(--text-muted)', fontSize: '0.875rem'}}>Click to select a file</span>
                </div>
              )}
            </div>
          </div>

          <button
            type="submit"
            disabled={!file || uploading}
            className="button"
            style={{opacity: (!file || uploading) ? 0.5 : 1, cursor: (!file || uploading) ? 'not-allowed' : 'pointer'}}
          >
            {uploading ? <Loader size={18} className="spin" /> : <UploadCloud size={18} />}
            {uploading ? 'Uploading...' : 'Upload & Process'}
          </button>
        </form>

        {error && (
          <div style={{marginTop: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--critical)'}}>
            <AlertCircle size={18} />
            <span>{error}</span>
          </div>
        )}

        {result && (
          <div style={{marginTop: '1.5rem'}}>
            {result.state === 'PENDING' && polling && (
              <div style={{display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--text-muted)'}}>
                <Loader size={18} className="spin" />
                <span>Processing scan file (Task: {result.task_id?.slice(0, 8)}...)...</span>
              </div>
            )}
            {result.state === 'SUCCESS' && (
              <div style={{display: 'flex', flexDirection: 'column', gap: '0.5rem'}}>
                <div style={{display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--low)'}}>
                  <CheckCircle size={18} />
                  <span>Scan processed successfully!</span>
                </div>
                {result.data && typeof result.data === 'object' && (
                  <div style={{fontSize: '0.85rem', color: 'var(--text-muted)', marginTop: '0.5rem'}}>
                    <div>Records processed: {result.data.processed_records || 0}</div>
                    {result.data.new_assets != null && <div>New assets: {result.data.new_assets}</div>}
                    {result.data.new_vulnerabilities != null && <div>New vulnerabilities: {result.data.new_vulnerabilities}</div>}
                    {result.data.new_associations != null && <div>New associations: {result.data.new_associations}</div>}
                    {result.data.reopened > 0 && <div>Reopened: {result.data.reopened}</div>}
                    {result.data.auto_remediated > 0 && (
                      <div>Closed automatically (no longer detected): {result.data.auto_remediated}</div>
                    )}
                  </div>
                )}
              </div>
            )}
            {result.state === 'FAILURE' && (
              <div style={{display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--critical)'}}>
                <AlertCircle size={18} />
                <span>Processing failed: {result.data?.message || 'Unknown error'}</span>
              </div>
            )}
            {result.state === 'TIMEOUT' && (
              <div style={{display: 'flex', alignItems: 'center', gap: '0.5rem', color: 'var(--high)'}}>
                <AlertCircle size={18} />
                <span>{result.data?.message}</span>
              </div>
            )}
          </div>
        )}
      </div>

      <ScanHistory refreshToken={historyToken} />
    </div>
  );
}