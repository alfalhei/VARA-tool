// Main initialization
document.addEventListener('DOMContentLoaded', function() {
    // DOM Elements
    const elements = {
        dropZone: document.getElementById('dropZone'),
        loadingState: document.getElementById('loadingState'),
        errorState: document.getElementById('errorState'),
        errorMessage: document.getElementById('errorMessage'),
        analysisResult: document.getElementById('analysisResult'),
        vulnType: document.getElementById('vulnType'),
        severityValue: document.getElementById('severityValue'),
        confidenceValue: document.getElementById('confidenceValue'),
        impactValue: document.getElementById('impactValue'),
        recommendationsList: document.getElementById('recommendationsList')
    };

    // Validate all required elements exist
    const missingElements = Object.entries(elements)
        .filter(([key, element]) => !element)
        .map(([key]) => key);

    if (missingElements.length > 0) {
        console.error('Missing required DOM elements:', missingElements);
        return;
    }

    // Event Handlers Setup
    function setupEventListeners() {
        // Prevent default drag behaviors
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            elements.dropZone.addEventListener(eventName, preventDefaults, false);
            document.body.addEventListener(eventName, preventDefaults, false);
        });

        // Highlight drop zone when item is dragged over it
        ['dragenter', 'dragover'].forEach(eventName => {
            elements.dropZone.addEventListener(eventName, highlight, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            elements.dropZone.addEventListener(eventName, unhighlight, false);
        });

        // Handle dropped files
        elements.dropZone.addEventListener('drop', handleDrop, false);
        
        // Handle click to upload
        elements.dropZone.addEventListener('click', () => {
            const input = document.createElement('input');
            input.type = 'file';
            input.accept = 'image/*,.txt';
            input.multiple = true;
            input.onchange = (e) => handleFiles(e.target.files);
            input.click();
        });
    }

    // Utility Functions
    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    function highlight(e) {
        elements.dropZone.classList.add('border-cyan-500');
    }

    function unhighlight(e) {
        elements.dropZone.classList.remove('border-cyan-500');
    }

    function handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;
        handleFiles(files);
    }

    function getCSRFToken() {
        const tokenElement = document.querySelector('meta[name="csrf-token"]');
        if (!tokenElement) {
            console.error('CSRF token meta tag not found');
            return null;
        }
        return tokenElement.content;
    }

    // File Handling
    async function handleFiles(files) {
        if (files.length === 0) {
            showError('No files selected');
            return;
        }

        const csrfToken = getCSRFToken();
        if (!csrfToken) {
            showError('Security token not found. Please refresh the page.');
            return;
        }

        const formData = new FormData();
        formData.append('file', files[0]);
        formData.append('csrf_token', csrfToken);

        try {
            await uploadFile(formData);
        } catch (error) {
            showError(error.message || 'An error occurred while uploading the file');
        }
    }

    // UI State Management
    function showLoading() {
        elements.loadingState.classList.remove('hidden');
        elements.errorState.classList.add('hidden');
        elements.analysisResult.classList.add('hidden');
    }

    function showError(message) {
        elements.loadingState.classList.add('hidden');
        elements.errorState.classList.remove('hidden');
        elements.errorMessage.textContent = message;
        elements.analysisResult.classList.add('hidden');
    }

    function showResults() {
        elements.loadingState.classList.add('hidden');
        elements.errorState.classList.add('hidden');
        elements.analysisResult.classList.remove('hidden');
    }

    // API Interaction
    async function uploadFile(formData) {
        showLoading();

        try {
            const response = await fetch('/upload_image', {
                method: 'POST',
                body: formData,
                headers: {
                    'X-CSRFToken': getCSRFToken()
                }
            });

            if (!response.ok) {
                const errorData = await response.json();
                throw new Error(errorData.error || 'Upload failed');
            }

            const result = await response.json();
            
            if (!result || !result.analysis) {
                throw new Error('Invalid response format from server');
            }

            displayResults(result);

        } catch (error) {
            console.error('Upload error:', error);
            showError(error.message || 'An error occurred during upload');
        }
    }

    // Results Display
    function displayResults(data) {
        try {
            if (!data.analysis) {
                throw new Error('No analysis data received');
            }

            showResults();

            // Update vulnerability type
            elements.vulnType.textContent = data.analysis.vulnerability_type || 'Unknown';
            
            // Update severity with appropriate styling
            const severityClass = getSeverityClass(data.analysis.severity);
            elements.severityValue.className = `px-2 py-1 rounded-full text-sm ${severityClass}`;
            elements.severityValue.textContent = data.analysis.severity || 'Unknown';
            
            // Update confidence score
            elements.confidenceValue.textContent = data.analysis.confidence ? 
                `${(data.analysis.confidence * 100).toFixed(1)}%` : 'N/A';
            
            // Update impact description
            elements.impactValue.textContent = data.analysis.impact || 'No impact information available';

            // Update recommendations
            updateRecommendations(data.analysis.recommendations || []);

        } catch (error) {
            console.error('Error displaying results:', error);
            showError('Error displaying analysis results');
        }
    }

    // Helper Functions
    function getSeverityClass(severity) {
        const classes = {
            'Critical': 'bg-red-500/10 text-red-500',
            'High': 'bg-orange-500/10 text-orange-500',
            'Medium': 'bg-yellow-500/10 text-yellow-500',
            'Low': 'bg-green-500/10 text-green-500',
            'Info': 'bg-blue-500/10 text-blue-500'
        };
        return classes[severity] || classes['Info'];
    }

    function updateRecommendations(recommendations) {
        elements.recommendationsList.innerHTML = '';
        
        if (recommendations.length === 0) {
            const li = document.createElement('li');
            li.className = 'text-gray-400';
            li.textContent = 'No recommendations available';
            elements.recommendationsList.appendChild(li);
            return;
        }

        recommendations.forEach(rec => {
            if (rec) {
                const li = document.createElement('li');
                li.className = 'flex items-center gap-2';
                li.innerHTML = `
                    <svg xmlns="http://www.w3.org/2000/svg" class="h-4 w-4 text-cyan-500" viewBox="0 0 20 20" fill="currentColor">
                        <path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clip-rule="evenodd" />
                    </svg>
                    ${rec}
                `;
                elements.recommendationsList.appendChild(li);
            }
        });
    }

    // Session Management
    async function loadSession(sessionId) {
        try {
            showLoading();
            
            const response = await fetch(`/api/session/${sessionId}`);
            if (!response.ok) {
                throw new Error('Failed to load session');
            }

            const data = await response.json();
            if (data.success) {
                displayResults(data);
            } else {
                throw new Error(data.error || 'Failed to load session data');
            }

        } catch (error) {
            console.error('Session load error:', error);
            showError(error.message || 'Error loading session');
        }
    }

    // Initialize event listeners
    setupEventListeners();

    // Expose necessary functions globally
    window.loadSession = loadSession;
});