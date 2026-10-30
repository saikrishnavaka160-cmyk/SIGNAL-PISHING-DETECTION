import React, { useState, useRef } from 'react';
import { DatasetReport } from '../types';
import { analyzeDataset, parseCSV, TITLES } from '../detector';

interface DatasetViewProps {
  showToast: (msg: string) => void;
}

export const DatasetView: React.FC<DatasetViewProps> = ({ showToast }) => {
  const [csvRaw, setCsvRaw] = useState('');
  const [csvFileName, setCsvFileName] = useState('Choose a CSV file');
  const [rowCount, setRowCount] = useState<number | null>(null);
  const [textColumn, setTextColumn] = useState('');
  const [labelColumn, setLabelColumn] = useState('');
  const [threshold, setThreshold] = useState(3);
  const [report, setReport] = useState<DatasetReport | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files && e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = () => {
      const text = String(reader.result || '');
      setCsvRaw(text);
      setCsvFileName(file.name);
      const rows = parseCSV(text);
      setRowCount(Math.max(0, rows.length - 1));
    };
    reader.readAsText(file);
  };

  const handleAnalyze = () => {
    if (!csvRaw) {
      showToast('Choose a CSV file first.');
      return;
    }
    const result = analyzeDataset(csvRaw, textColumn, labelColumn, threshold);
    if (result.error) {
      showToast(result.error);
      return;
    }
    if (result.report) {
      setReport(result.report);
    }
  };

  const stopPercent = threshold * 10;
  const sliderBackground = `linear-gradient(to right, #8caeff ${stopPercent}%, #e7ebf1 ${stopPercent}%)`;

  const risks: Array<'High' | 'Suspicious' | 'Low'> = ['High', 'Suspicious', 'Low'];
  const maxRisk = report
    ? Math.max(1, report.risks.High, report.risks.Suspicious, report.risks.Low)
    : 1;

  return (
    <section className="view" id="dataset-view">
      <div className="subpage-heading">
        <div className="eyebrow">
          <span className="eyebrow-line"></span> BATCH ANALYSIS
        </div>
        <h1>Review a dataset.</h1>
        <p>See how the rules perform across a labeled email collection.</p>
      </div>

      <div className="dataset-layout">
        <section className="panel dataset-input-panel">
          <div className="section-kicker">01 <span>·</span> YOUR DATA</div>
          <h2>Import a CSV file</h2>
          <p className="muted-copy">
            Choose a CSV with one email per row. Your dataset is processed in your browser and never uploaded.
          </p>

          <input
            id="csv-file"
            ref={fileInputRef}
            type="file"
            accept=".csv,text/csv"
            hidden
            onChange={handleFileChange}
          />
          <button
            className="csv-drop"
            id="browse-csv"
            type="button"
            onClick={() => fileInputRef.current?.click()}
          >
            <span className="csv-icon">▤</span>
            <strong id="csv-filename">{csvFileName}</strong>
            <small>Browse your device · .CSV</small>
            <span className="csv-arrow">→</span>
          </button>

          {rowCount !== null && (
            <div id="csv-file-status" className="file-status">
              Ready to scan · {rowCount.toLocaleString()} data rows detected
            </div>
          )}

          <div className="field-pair">
            <div>
              <label className="field-label" htmlFor="text-column">
                EMAIL TEXT COLUMN
              </label>
              <input
                className="text-input"
                id="text-column"
                type="text"
                placeholder="Auto-detect"
                value={textColumn}
                onChange={(e) => setTextColumn(e.target.value)}
              />
            </div>
            <div>
              <label className="field-label" htmlFor="label-column">
                LABEL COLUMN <span>(OPTIONAL)</span>
              </label>
              <input
                className="text-input"
                id="label-column"
                type="text"
                placeholder="Auto-detect"
                value={labelColumn}
                onChange={(e) => setLabelColumn(e.target.value)}
              />
            </div>
          </div>

          <div className="threshold-control">
            <div className="threshold-heading">
              <label className="field-label" htmlFor="threshold-input">
                POSITIVE DETECTION THRESHOLD
              </label>
              <span>
                <b id="threshold-value">{threshold}</b> points
              </span>
            </div>
            <input
              id="threshold-input"
              type="range"
              min="0"
              max="10"
              value={threshold}
              style={{ background: sliderBackground }}
              onChange={(e) => setThreshold(Number(e.target.value))}
            />
            <div className="range-labels">
              <span>More sensitive</span>
              <span>Fewer alerts</span>
            </div>
          </div>

          <button className="button-primary full-width" id="analyze-csv" type="button" onClick={handleAnalyze}>
            <span className="button-spark">✳</span> Analyze dataset <span className="button-arrow">→</span>
          </button>
          <p className="local-note">
            <span className="privacy-mini">⌑</span> Only aggregate results are displayed. Email contents stay on your device.
          </p>
        </section>

        <section className="panel dataset-result-panel">
          {!report ? (
            <div className="dataset-empty" id="dataset-empty">
              <div className="dataset-empty-icon">
                ▤<span>✳</span>
              </div>
              <h2>Dataset insights, at a glance</h2>
              <p>
                Import a labeled CSV to see risk distribution,<br />
                indicator frequency, and evaluation metrics.
              </p>
              <div className="metric-skeleton">
                <span></span>
                <span></span>
                <span></span>
              </div>
            </div>
          ) : (
            <div id="dataset-result">
              <div className="dataset-result-header">
                <h2>Dataset overview</h2>
                <span>Threshold: {report.threshold} points</span>
              </div>

              <div className="metric-grid">
                <div className="metric-box">
                  <span>Rows scanned</span>
                  <strong>{report.scanned.toLocaleString()}</strong>
                </div>
                <div className="metric-box">
                  <span>Average score</span>
                  <strong>{report.average.toFixed(2)}</strong>
                </div>
                <div className="metric-box">
                  <span>Blank rows skipped</span>
                  <strong>{report.blank.toLocaleString()}</strong>
                </div>
                <div className="metric-box">
                  <span>Unrecognized labels</span>
                  <strong>{report.skipped.toLocaleString()}</strong>
                </div>
              </div>

              <div className="dataset-section-title">Risk distribution</div>
              {risks.map((name) => {
                const css = name === 'High' ? 'high' : name === 'Suspicious' ? 'suspicious' : '';
                const count = report.risks[name];
                const widthPercent = (count / maxRisk) * 100;
                return (
                  <div key={name} className="bar-row">
                    <span>{name}</span>
                    <div className="bar-track">
                      <div className={`bar-fill ${css}`} style={{ width: `${widthPercent}%` }}></div>
                    </div>
                    <span className="bar-count">{count}</span>
                  </div>
                );
              })}

              <div className="dataset-section-title">Most common indicators</div>
              <table className="indicator-table">
                <tbody>
                  {report.indicators.length > 0 ? (
                    report.indicators.map((item) => (
                      <tr key={item.code}>
                        <td>{TITLES[item.code] || item.code}</td>
                        <td>{item.count}</td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td>No rule indicators found</td>
                      <td>0</td>
                    </tr>
                  )}
                </tbody>
              </table>

              {report.evaluation && (
                <>
                  <div className="dataset-section-title">
                    Evaluation · {report.evaluation.evaluated} recognized labels
                  </div>
                  <div className="confusion-grid">
                    <div className="confusion-cell">
                      <small>True positive</small>
                      <b>{report.evaluation.tp}</b>
                    </div>
                    <div className="confusion-cell">
                      <small>False positive</small>
                      <b>{report.evaluation.fp}</b>
                    </div>
                    <div className="confusion-cell">
                      <small>False negative</small>
                      <b>{report.evaluation.fn}</b>
                    </div>
                    <div className="confusion-cell">
                      <small>True negative</small>
                      <b>{report.evaluation.tn}</b>
                    </div>
                  </div>
                  <div className="metric-grid">
                    <div className="metric-box">
                      <span>Accuracy</span>
                      <strong>{report.evaluation.accuracy}</strong>
                    </div>
                    <div className="metric-box">
                      <span>Precision</span>
                      <strong>{report.evaluation.precision}</strong>
                    </div>
                    <div className="metric-box">
                      <span>Recall</span>
                      <strong>{report.evaluation.recall}</strong>
                    </div>
                    <div className="metric-box">
                      <span>F1 score</span>
                      <strong>{report.evaluation.f1}</strong>
                    </div>
                  </div>
                </>
              )}

              <p className="dataset-footnote">
                Aggregate results only. Evaluation depends on accurate labels and representative data. Use these rules as
                one part of your email security process.
              </p>
            </div>
          )}
        </section>
      </div>
    </section>
  );
};
