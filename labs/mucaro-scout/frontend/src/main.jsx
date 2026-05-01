import React, { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import './styles.css';

const API_URL = import.meta.env.VITE_API_URL || '/api';

const DIALECT_HINTS = {
  kql: 'source_ip: "10.0.0.5" and severity: high',
  esql: 'FROM logs | WHERE severity == "high" | LIMIT 100',
};

const TIME_RANGES = {
  '15m': { label: 'Last 15 minutes', ms: 15 * 60 * 1000 },
  '1h': { label: 'Last 60 minutes', ms: 60 * 60 * 1000 },
  '24h': { label: 'Last 24 hours', ms: 24 * 60 * 60 * 1000 },
  '7d': { label: 'Last 7 days', ms: 7 * 24 * 60 * 60 * 1000 },
  all: { label: 'All time', ms: null },
};

function cleanValue(value) {
  return value.replace(/^['"]|['"]$/g, '').trim();
}

function parseQueryByDialect(rawQuery, dialect) {
  const filters = {};
  let text = rawQuery.trim();

  if (!text) return { query: '', filters };

  if (dialect === 'kql') {
    text = text.replace(/\b([a-zA-Z_][\w.]*)\s*:\s*("[^"]+"|'[^']+'|[^\s)]+)/g, (_, key, value) => {
      filters[key] = cleanValue(value);
      return ' ';
    });
    text = text.replace(/\b(and|or)\b/gi, ' ');
  }

  if (dialect === 'esql') {
    const whereMatch = text.match(/\bWHERE\b(.+?)(\bLIMIT\b|$)/i);
    if (whereMatch) {
      whereMatch[1].replace(/\b([a-zA-Z_][\w.]*)\s*(==|=)\s*("[^"]+"|'[^']+'|[^\s|]+)/g, (_, key, _op, value) => {
        filters[key] = cleanValue(value);
        return '';
      });
    }
    text = text
      .replace(/\bFROM\b[^|]+/gi, ' ')
      .replace(/\|?\s*\bWHERE\b.+?(\bLIMIT\b|$)/gi, ' ')
      .replace(/\|?\s*\bLIMIT\b\s+\d+/gi, ' ');
  }

  return { query: text.replace(/\s+/g, ' ').trim(), filters };
}

function getTimeBounds(rangeKey) {
  const range = TIME_RANGES[rangeKey];
  if (!range || range.ms === null) return { start_time: null, end_time: null };
  const end = new Date();
  const start = new Date(end.getTime() - range.ms);
  return { start_time: start.toISOString(), end_time: end.toISOString() };
}

function App() {
  const [file, setFile] = useState(null);
  const [uploadStatus, setUploadStatus] = useState('');
  const [splunkStatus, setSplunkStatus] = useState('');
  const [query, setQuery] = useState('');
  const [queryDialect, setQueryDialect] = useState('kql');
  const [timeRange, setTimeRange] = useState('all');
  const [loading, setLoading] = useState(false);
  const [uploadModalOpen, setUploadModalOpen] = useState(false);
  const [viewMode, setViewMode] = useState('scout');
  const [results, setResults] = useState([]);
  const [total, setTotal] = useState(0);
  const [error, setError] = useState('');

  async function uploadFile(event) {
    event.preventDefault();
    if (!file) return;
    setUploadStatus('Uploading and indexing...');
    setError('');
    const form = new FormData();
    form.append('file', file);
    try {
      const res = await fetch(`${API_URL}/ingest/upload`, { method: 'POST', body: form });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      setUploadStatus(`Indexed ${data.ingested} events${data.errors ? ' with bulk errors' : ''}.`);
    } catch (err) {
      setUploadStatus('');
      setError(`Upload failed: ${err.message}`);
    }
  }

  async function startSplunk() {
    setSplunkStatus('Starting Splunk... first boot can take a few minutes.');
    setError('');
    try {
      const res = await fetch(`${API_URL}/integrations/splunk/start`, { method: 'POST' });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      setSplunkStatus(data.message || 'Splunk is starting.');
      window.open(`${window.location.protocol}//${window.location.hostname}:8001`, '_blank', 'noreferrer');
    } catch (err) {
      setSplunkStatus('');
      setError(`Splunk start failed: ${err.message}`);
    }
  }

  async function search(event) {
    event?.preventDefault();
    setLoading(true);
    setError('');
    const parsed = parseQueryByDialect(query, queryDialect);
    const bounds = getTimeBounds(timeRange);
    try {
      const res = await fetch(`${API_URL}/search`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: parsed.query, ...bounds, filters: parsed.filters, page: 1, size: 100 }),
      });
      if (!res.ok) throw new Error(await res.text());
      const data = await res.json();
      setResults(data.results || []);
      setTotal(data.total || 0);
    } catch (err) {
      setError(`Search failed: ${err.message}`);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    search();
  }, []);

  return (
    <main className="shell">
      <header className="app-header">
        <div className="brand-mark">
          <span className="logo-dot">M</span>
          <div>
            <p className="eyebrow">Múcaro Scout</p>
            <p className="tagline">Lightweight SQLite JSON log viewer with optional OpenSearch and Splunk labs.</p>
          </div>
        </div>

        <div className="header-actions">
          <div className="mode-toggle" role="group" aria-label="View mode">
            <button type="button" className={viewMode === 'opensearch' ? 'active' : ''} onClick={() => setViewMode('opensearch')}>Dashboards</button>
            <button type="button" className={viewMode === 'scout' ? 'active' : ''} onClick={() => setViewMode('scout')}>Guided Search</button>
            <button type="button" onClick={startSplunk}>Splunk</button>
          </div>
          <button type="button" className="upload-button" onClick={() => setUploadModalOpen(true)}>Upload data</button>
        </div>
        {(uploadStatus || splunkStatus) && <div className="header-status">{splunkStatus || uploadStatus}</div>}
      </header>

      {viewMode === 'opensearch' ? (
        <section className="opensearch-home">
          <div className="panel opensearch-card primary-card">
            <p className="eyebrow">Default workspace</p>
            <h1>Dashboards</h1>
            <p>Use the Kibana-style Dashboards experience for raw exploration, visualizations, index inspection, and advanced hunt workflows.</p>
            <div className="link-row">
              <a className="big-link" href={`${window.location.protocol}//${window.location.hostname}:5601`} target="_blank" rel="noreferrer">Open Dashboards</a>
              <a className="secondary-link" href={`${window.location.protocol}//${window.location.hostname}:9200`} target="_blank" rel="noreferrer">Open API</a>
            </div>
          </div>
          <div className="panel opensearch-card">
            <h2>Current index</h2>
            <code>logs-normalized</code>
            <p className="hint">Uploaded data is normalized to ECS-inspired fields before being indexed here.</p>
          </div>
          <div className="panel opensearch-card">
            <h2>Guided Search</h2>
            <p>Use Guided Search for a lightweight SQLite-backed JSON log viewer before moving into Dashboards.</p>
            <button type="button" onClick={() => setViewMode('scout')}>Switch to Guided Search</button>
          </div>
        </section>
      ) : (
        <>
          <section className="search-grid">
            <form className="panel search-panel opensearch-search" onSubmit={search}>
              <div className="search-bar-row">
                <div className="query-wrap">
                  <label>Search</label>
                  <textarea value={query} onChange={(e) => setQuery(e.target.value)} placeholder={DIALECT_HINTS[queryDialect]} rows="4" />
                </div>
                <div className="time-picker">
                  <label>Time range</label>
                  <select value={timeRange} onChange={(e) => setTimeRange(e.target.value)} aria-label="Time range">
                    {Object.entries(TIME_RANGES).map(([key, range]) => (
                      <option key={key} value={key}>{range.label}</option>
                    ))}
                  </select>
                  <label>Mode</label>
                  <select value={queryDialect} onChange={(e) => setQueryDialect(e.target.value)} aria-label="Query dialect">
                    <option value="kql">KQL</option>
                    <option value="esql">ES|QL</option>
                  </select>
                  <button type="submit">{loading ? 'Searching...' : 'Search'}</button>
                </div>
              </div>
              <p className="hint">KQL filters such as <code>source_ip: "10.0.0.5" and severity: high</code> are parsed into normalized field filters.</p>
            </form>
          </section>
        </>
      )}

      {error && <div className="notice error">{error}</div>}

      {uploadModalOpen && (
        <div className="modal-backdrop" onClick={() => setUploadModalOpen(false)}>
          <section className="upload-modal" onClick={(event) => event.stopPropagation()} role="dialog" aria-modal="true" aria-labelledby="upload-modal-title">
            <div className="modal-header">
              <div>
                <p className="eyebrow">Múcaro Scout</p>
                <h2 id="upload-modal-title">Upload data</h2>
                <p className="hint">Drop in classroom logs and Scout will normalize them into the local SQLite viewer.</p>
              </div>
              <button type="button" className="ghost-button" onClick={() => setUploadModalOpen(false)}>Close</button>
            </div>

            <form className="upload-form" onSubmit={uploadFile}>
              <label className="drop-zone">
                <span>Choose log file</span>
                <strong>{file ? file.name : 'CSV, JSON, or JSONL'}</strong>
                <input type="file" accept=".csv,.json,.jsonl" onChange={(e) => setFile(e.target.files?.[0] || null)} />
              </label>
              <p className="hint">Data is normalized into the ECS-inspired Mucaro Scout schema and stored in SQLite.</p>
              <button type="submit" disabled={!file}>Upload & index</button>
              {uploadStatus && <div className="notice success">{uploadStatus}</div>}
            </form>

            <div className="modal-section">
              <h3>Normalization target</h3>
              <ul>
                <li>@timestamp</li>
                <li>source_ip / destination_ip</li>
                <li>user / host</li>
                <li>domain</li>
                <li>event_type / severity</li>
                <li>raw_message</li>
              </ul>
            </div>
          </section>
        </div>
      )}

      {viewMode === 'scout' && (
        <section className="results">
          <div className="results-header">
            <h2>Events</h2>
            <span>Showing {results.length.toLocaleString()} of {total.toLocaleString()} matches</span>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Severity</th>
                  <th>Event</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>User</th>
                  <th>Host</th>
                  <th>Domain</th>
                  <th>Message</th>
                </tr>
              </thead>
              <tbody>
                {results.length === 0 ? (
                  <tr><td colSpan="9" className="empty">No events yet. Ingest sample data, then run a search.</td></tr>
                ) : results.map((row, i) => (
                  <tr key={`${row['@timestamp']}-${i}`}>
                    <td>{row['@timestamp']}</td>
                    <td><span className={`pill ${row.severity || 'info'}`}>{row.severity}</span></td>
                    <td>{row.event_type}</td>
                    <td>{row.source_ip}</td>
                    <td>{row.destination_ip}</td>
                    <td>{row.user}</td>
                    <td>{row.host}</td>
                    <td>{row.domain}</td>
                    <td className="message">{row.raw_message}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      )}
    </main>
  );
}

createRoot(document.getElementById('root')).render(<App />);
