document.addEventListener('DOMContentLoaded', () => {
    const uploadForm = document.getElementById('uploadForm');
    const resultsDiv = document.getElementById('analysis-results');
    const vulnerabilityType = document.getElementById('vulnerability-type');
    const confidence = document.getElementById('confidence');
    const top3Predictions = document.getElementById('top-predictions');

    uploadForm.addEventListener('submit', async (e) => {
        e.preventDefault();
        const formData = new FormData(uploadForm);
        
        try {
            const response = await fetch('/api/analyze', {
                method: 'POST',
                body: formData
            });
            
            if (!response.ok) {
                throw new Error('Analysis failed');
            }

            const result = await response.json();
            displayResults(result);
        } catch (error) {
            console.error('Error:', error);
            alert('Error: ' + error.message);
        }
    });

    function displayResults(result) {
        vulnerabilityType.textContent = result.vulnerability_type;
        confidence.textContent = result.confidence.toFixed(2);
        top3Predictions.innerHTML = result.top3_predictions.map(pred => 
            `${pred[0]}: ${pred[1].toFixed(2)}`
        ).join('<br>');
        resultsDiv.style.display = 'block';
    }
});
