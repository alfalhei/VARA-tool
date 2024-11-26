import React, { useState, useCallback } from 'react';
import { AlertCircle } from 'lucide-react';
import { Alert, AlertTitle, AlertDescription } from '@/components/ui/alert';
import { generateFileId } from '../../utils/fileUtils';
import { uploadFiles } from '../../utils/api';
import DropZone from './DropZone';
import FileList from './FileList';
import ResultsGrid from './ResultsGrid';

const BatchUploadAnalyzer = () => {
  const [files, setFiles] = useState([]);
  const [uploading, setUploading] = useState(false);
  const [results, setResults] = useState([]);
  const [error, setError] = useState(null);

  const handleFilesAdded = useCallback((newFiles) => {
    if (newFiles.length === 0) return;

    const filesWithIds = newFiles.map(file => ({
      file,
      id: generateFileId(),
      status: 'pending',
      progress: 0
    }));

    setFiles(prev => [...prev, ...filesWithIds]);
    setError(null); // Clear any previous errors
  }, []);

  const handleRemoveFile = useCallback((id) => {
    setFiles(prev => prev.filter(f => f.id !== id));
  }, []);

  const startAnalysis = async () => {
    if (files.length === 0) return;

    setUploading(true);
    setError(null);

    try {
      // Update UI to show upload started
      setFiles(prev => prev.map(f => ({
        ...f,
        status: 'uploading',
        progress: 0
      })));

      const response = await uploadFiles(files);

      if (response.success) {
        // Update UI with results
        setResults(response.results);
        
        // Clear files after successful upload
        setFiles([]);
        
        // Show success state for each file
        setFiles(prev => prev.map(f => ({
          ...f,
          status: 'complete',
          progress: 100
        })));
      } else {
        throw new Error(response.error || 'Analysis failed');
      }
    } catch (err) {
      setError(err.message);
      
      // Update UI to show error state
      setFiles(prev => prev.map(f => ({
        ...f,
        status: 'error',
        error: err.message
      })));
    } finally {
      setUploading(false);
    }
  };

  return (
    <div className="space-y-6">
      {/* File Upload Section */}
      <div className="bg-zinc-900 rounded-lg shadow-xl p-6">
        <h2 className="text-xl font-bold text-white mb-6">
          Batch VAPT Analysis
        </h2>

        {/* Drop Zone */}
        <DropZone onFilesAdded={handleFilesAdded} />

        {/* File List */}
        {files.length > 0 && (
          <>
            <div className="mt-6">
              <FileList
                files={files}
                uploading={uploading}
                onRemoveFile={handleRemoveFile}
              />
            </div>

            <div className="mt-4 flex justify-end">
              <button
                onClick={startAnalysis}
                disabled={uploading}
                className={`px-4 py-2 rounded-lg text-white transition-colors ${
                  uploading
                    ? 'bg-zinc-600 cursor-not-allowed'
                    : 'bg-cyan-600 hover:bg-cyan-700'
                }`}
              >
                {uploading ? 'Analyzing...' : 'Start Batch Analysis'}
              </button>
            </div>
          </>
        )}

        {/* Error Alert */}
        {error && (
          <div className="mt-4">
            <Alert variant="destructive">
              <AlertCircle className="w-4 h-4" />
              <AlertTitle>Error</AlertTitle>
              <AlertDescription>{error}</AlertDescription>
            </Alert>
          </div>
        )}
      </div>

      {/* Results Section */}
      {results.length > 0 && (
        <div className="bg-zinc-900 rounded-lg shadow-xl p-6">
          <ResultsGrid results={results} />
        </div>
      )}
    </div>
  );
};

export default BatchUploadAnalyzer;