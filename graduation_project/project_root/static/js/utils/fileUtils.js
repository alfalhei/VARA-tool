export const validateFile = (file) => {
  const allowedTypes = ['image/jpeg', 'image/png', 'image/gif', 'text/plain'];
  const maxSize = 16 * 1024 * 1024; // 16MB

  if (!allowedTypes.includes(file.type)) {
    throw new Error(`File type ${file.type} is not supported`);
  }

  if (file.size > maxSize) {
    throw new Error('File size exceeds 16MB limit');
  }

  return true;
};

export const generateFileId = () => {
  return crypto.randomUUID();
};

export const getFileIcon = (fileType) => {
  return fileType.startsWith('image/') ? 'Camera' : 'FileText';
};

export const formatFileSize = (bytes) => {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};