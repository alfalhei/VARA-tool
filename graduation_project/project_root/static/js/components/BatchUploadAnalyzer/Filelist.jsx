import React from 'react';
import { Camera, FileText, XCircle } from 'lucide-react';
import { formatFileSize } from '../../utils/fileUtils';

const FileList = ({ files, uploading, onRemoveFile }) => {
  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <h3 className="text-lg font-medium text-white">
          Files to Analyze ({files.length})
        </h3>
      </div>

      <div className="space-y-2">
        {files.map(file => (
          <div key={file.id} className="bg-zinc-800/50 rounded-lg p-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                {file.file.type.includes('image') ? (
                  <Camera className="w-5 h-5 text-cyan-500" />
                ) : (
                  <FileText className="w-5 h-5 text-cyan-500" />
                )}
                <div>
                  <span className="text-white block">{file.file.name}</span>
                  <span className="text-zinc-400 text-sm">
                    {formatFileSize(file.file.size)}
                  </span>
                </div>
              </div>
              {!uploading && (
                <button
                  onClick={() => onRemoveFile(file.id)}
                  className="text-zinc-400 hover:text-red-500"
                >
                  <XCircle className="w-5 h-5" />
                </button>
              )}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default FileList;