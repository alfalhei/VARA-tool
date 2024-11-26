import React, { useCallback } from 'react';
import { Upload } from 'lucide-react';
import { validateFile } from '../../utils/fileUtils';

const DropZone = ({ onFilesAdded }) => {
  const handleDrop = useCallback((e) => {
    e.preventDefault();
    const droppedFiles = Array.from(e.dataTransfer?.files || []);
    
    try {
      droppedFiles.forEach(file => validateFile(file));
      onFilesAdded(droppedFiles);
    } catch (err) {
      // Handle error through UI
      console.error(err);
    }
  }, [onFilesAdded]);

  const handleFileSelect = useCallback((e) => {
    const selectedFiles = Array.from(e.target.files || []);
    
    try {
      selectedFiles.forEach(file => validateFile(file));
      onFilesAdded(selectedFiles);
    } catch (err) {
      // Handle error through UI
      console.error(err);
    }
  }, [onFilesAdded]);

  return (
    <div
      onDrop={handleDrop}
      onDragOver={(e) => e.preventDefault()}
      className="border-2 border-dashed border-zinc-700 rounded-lg p-8 text-center hover:border-cyan-600 transition-colors"
    >
      <div className="flex flex-col items-center gap-4">
        <Upload className="w-12 h-12 text-cyan-500" />
        <div>
          <p className="text-lg font-medium text-white">Drop files here</p>
          <p className="text-sm text-zinc-400">Upload multiple files for batch analysis</p>
          <p className="text-xs text-zinc-500 mt-2">Supported formats: PNG, JPG, GIF, TXT</p>
          <p className="text-xs text-zinc-500">Maximum size: 16MB per file</p>
        </div>
        <input
          type="file"
          multiple
          onChange={handleFileSelect}
          className="hidden"
          id="file-upload"
          accept=".png,.jpg,.jpeg,.gif,.txt"
        />
        <label
          htmlFor="file-upload"
          className="px-4 py-2 bg-cyan-600 text-white rounded-lg hover:bg-cyan-700 cursor-pointer"
        >
          Select Files
        </label>
      </div>
    </div>
  );
};

export default DropZone;