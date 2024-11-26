import React from 'react';
import { downloadReport } from '../../utils/api';

const ResultsGrid = ({ results }) => {
  const handleDownload = async (sessionId) => {
    try {
      await downloadReport(sessionId);
    } catch (err) {
      console.error('Failed to download report:', err);
    }
  };

  return (
    <div className="space-y-4">
      <h3 className="text-lg font-medium text-white">Analysis Results</h3>
      <div className="grid gap-4 md:grid-cols-2">
        {results.map((result, index) => (
          <div key={index} className="bg-zinc-800/50 rounded-lg p-4">
            <div className="flex justify-between items-center mb-2">
              <span className="text-white font-medium">
                {result.filename}
              </span>
              {result.error ? (
                <span className="px-2 py-1 bg-red-500/10 text-red-500 rounded text-sm">
                  Failed
                </span>
              ) : (
                <span className={`px-2 py-1 rounded text-sm ${
                  result.analysis.severity === 'Critical' ? 'bg-red-500/10 text-red-500' :
                  result.analysis.severity === 'High' ? 'bg-orange-500/10 text-orange-500' :
                  result.analysis.severity === 'Medium' ? 'bg-yellow-500/10 text-yellow-500' :
                  'bg-green-500/10 text-green-500'
                }`}>
                  {result.analysis.severity}
                </span>
              )}
            </div>
            
            {result.error ? (
              <p className="text-sm text-red-400">{result.error}</p>
            ) : (
              <>
                <p className="text-sm text-zinc-400 mb-2">
                  {result.analysis.vulnerability_type}
                </p>
                <div className="space-y-1">
                  {result.analysis.recommendations.slice(0, 2).map((rec, idx) => (
                    <p key={idx} className="text-sm text-cyan-400">• {rec}</p>
                  ))}
                </div>
                <button
                  onClick={() => handleDownload(result.sessionId)}
                  className="mt-4 text-sm text-cyan-500 hover:text-cyan-400"
                >
                  Download Report
                </button>
              </>
            )}
          </div>
        ))}
      </div>
    </div>
  );
};

export default ResultsGrid;