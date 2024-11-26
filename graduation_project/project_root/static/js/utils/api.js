const getCsrfToken = () => {
  return document.querySelector('[name=csrf_token]').value;
};

export const uploadFiles = async (files) => {
  const formData = new FormData();
  files.forEach(fileItem => {
    formData.append('files[]', fileItem.file);
  });

  const response = await fetch('/batch_upload', {
    method: 'POST',
    body: formData,
    headers: {
      'X-CSRFToken': getCsrfToken()
    }
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || 'Upload failed');
  }

  return response.json();
};

export const downloadReport = async (sessionId) => {
  const response = await fetch(`/api/report/${sessionId}`, {
    headers: {
      'X-CSRFToken': getCsrfToken()
    }
  });

  if (!response.ok) {
    throw new Error('Failed to generate report');
  }

  const blob = await response.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `VAPT_Report_${sessionId}.pdf`;
  document.body.appendChild(a);
  a.click();
  window.URL.revokeObjectURL(url);
  document.body.removeChild(a);
};