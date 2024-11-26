const Dashboard = () => {
    const [analysisResult, setAnalysisResult] = React.useState(null);
    const [isAnalyzing, setIsAnalyzing] = React.useState(false);
    const [error, setError] = React.useState(null);
    const [selectedSession, setSelectedSession] = React.useState(null);
    const [recentSessions] = React.useState([
      {
        id: 1,
        timestamp: '2024-10-31 14:23',
        vulnerability: 'SQL Injection',
        severity: 'Critical',
      },
      {
        id: 2,
        timestamp: '2024-10-31 13:15',
        vulnerability: 'XSS Attack',
        severity: 'High',
      },
      {
        id: 3,
        timestamp: '2024-10-31 11:30',
        vulnerability: 'Path Traversal',
        severity: 'Medium',
      },
    ]);
  
    const handleFileUpload = async (event) => {
      const file = event.target.files[0];
      if (!file) return;
  
      setIsAnalyzing(true);
      setError(null);
  
      const formData = new FormData();
      formData.append('file', file);
  
      try {
        const response = await fetch('/upload_image', {
          method: 'POST',
          body: formData,
          credentials: 'same-origin'
        });
  
        if (!response.ok) {
          throw new Error(await response.text());
        }
  
        const result = await response.json();
        setAnalysisResult(result.analysis);
      } catch (err) {
        setError(err.message);
      } finally {
        setIsAnalyzing(false);
      }
    };
  
    const getSeverityColor = (severity) => {
      const colors = {
        Critical: 'text-red-500',
        High: 'text-orange-500',
        Medium: 'text-yellow-500',
        Low: 'text-green-500'
      };
      return colors[severity] || 'text-gray-500';
    };
  
    const getSeverityBgColor = (severity) => {
      const colors = {
        Critical: 'bg-red-500/10',
        High: 'bg-orange-500/10',
        Medium: 'bg-yellow-500/10',
        Low: 'bg-green-500/10'
      };
      return colors[severity] || 'bg-gray-500/10';
    };
  
    return (
      <div className="flex h-screen bg-zinc-950">
        {/* Sessions Sidebar */}
        <div className="w-80 border-r border-zinc-800 flex flex-col">
          <div className="p-4 border-b border-zinc-800">
            <div className="flex items-center gap-2 text-zinc-100">
              <lucide.Terminal className="h-5 w-5" />
              <h2 className="text-xl font-semibold">VAPT Analysis</h2>
            </div>
          </div>
          
          <div className="p-4">
            <div className="flex items-center gap-2 text-zinc-400 mb-4">
              <lucide.Clock className="h-4 w-4" />
              <h3 className="text-sm font-medium">Recent Sessions</h3>
            </div>
            
            <div className="space-y-2">
              {recentSessions.map((session) => (
                <div
                  key={session.id}
                  onClick={() => setSelectedSession(session)}
                  className={`p-3 rounded-lg cursor-pointer transition-all ${
                    selectedSession?.id === session.id
                      ? 'bg-zinc-800'
                      : 'bg-zinc-900 hover:bg-zinc-800/50'
                  }`}
                >
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-zinc-300">{session.vulnerability}</span>
                    <lucide.ChevronRight className="h-4 w-4 text-zinc-600" />
                  </div>
                  <div className="flex items-center justify-between mt-2">
                    <span className="text-xs text-zinc-500">{session.timestamp}</span>
                    <span className={`text-xs px-2 py-1 rounded ${getSeverityBgColor(session.severity)} ${getSeverityColor(session.severity)}`}>
                      {session.severity}
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
  
        {/* Main Content */}
        <div className="flex-1 overflow-auto">
          <header className="bg-zinc-900/50 border-b border-zinc-800 backdrop-blur supports-[backdrop-filter]:bg-zinc-900/50">
            <div className="flex items-center justify-between h-14 px-6">
              <div className="flex items-center gap-2">
                <lucide.Activity className="h-5 w-5 text-zinc-400" />
                <span className="text-zinc-100">Security Analysis</span>
              </div>
              <div className="flex items-center gap-4">
                <span className="text-zinc-400">Welcome, admin</span>
                <a href="/logout" className="text-red-500 hover:text-red-400 transition-colors">
                  Logout
                </a>
              </div>
            </div>
          </header>
  
          <main className="p-6">
            <div className="max-w-4xl mx-auto">
              <div className="bg-zinc-900 border border-zinc-800 rounded-lg shadow-xl">
                <div className="p-6">
                  <h2 className="text-xl font-semibold text-zinc-100 mb-6">Upload Image for Analysis</h2>
                  
                  <div className="border-2 border-dashed border-zinc-800 rounded-lg p-12 hover:border-zinc-700 transition-colors">
                    <div className="flex flex-col items-center">
                      <input
                        type="file"
                        id="fileInput"
                        onChange={handleFileUpload}
                        className="hidden"
                        accept="image/*"
                      />
                      <label
                        htmlFor="fileInput"
                        className="cursor-pointer flex flex-col items-center"
                      >
                        <lucide.Upload className="h-12 w-12 text-zinc-500 mb-3" />
                        <span className="text-zinc-400">
                          Click to upload or drag and drop
                        </span>
                      </label>
                    </div>
                  </div>
  
                  {isAnalyzing && (
                    <div className="mt-6 flex items-center justify-center text-zinc-300 gap-3">
                      <div className="animate-spin rounded-full h-5 w-5 border-2 border-zinc-500 border-t-zinc-200" />
                      Analyzing vulnerabilities...
                    </div>
                  )}
  
                  {error && (
                    <div className="mt-6 p-4 bg-red-900/20 border border-red-900/50 rounded-lg flex items-start gap-3">
                      <lucide.AlertTriangle className="h-5 w-5 text-red-500 mt-0.5" />
                      <div>
                        <h4 className="font-medium text-red-500">Analysis Error</h4>
                        <p className="text-red-400">{error}</p>
                      </div>
                    </div>
                  )}
  
                  {analysisResult && (
                    <div className="mt-8 space-y-6">
                      <h3 className="text-lg font-semibold text-zinc-100 flex items-center gap-2">
                        <lucide.FileWarning className="h-5 w-5 text-zinc-400" />
                        Analysis Results
                      </h3>
  
                      <div className="grid gap-4 md:grid-cols-2">
                        <div className={`p-4 rounded-lg ${getSeverityBgColor(analysisResult.severity)} border border-zinc-800`}>
                          <div className="flex items-center gap-2 mb-4">
                            <lucide.Shield className="h-5 w-5 text-zinc-400" />
                            <h4 className="font-medium text-zinc-100">Vulnerability Details</h4>
                          </div>
                          <div className="space-y-3 text-sm">
                            <div>
                              <span className="text-zinc-400">Type:</span>
                              <span className={`ml-2 ${getSeverityColor(analysisResult.severity)}`}>
                                {analysisResult.vulnerability_type}
                              </span>
                            </div>
                            <div>
                              <span className="text-zinc-400">Severity:</span>
                              <span className={`ml-2 ${getSeverityColor(analysisResult.severity)}`}>
                                {analysisResult.severity}
                              </span>
                            </div>
                            <div>
                              <span className="text-zinc-400">Confidence:</span>
                              <span className="ml-2 text-zinc-300">
                                {(analysisResult.confidence * 100).toFixed(1)}%
                              </span>
                            </div>
                          </div>
                        </div>
  
                        <div className="p-4 bg-zinc-800/50 rounded-lg border border-zinc-800">
                          <div className="flex items-center gap-2 mb-4">
                            <lucide.Eye className="h-5 w-5 text-zinc-400" />
                            <h4 className="font-medium text-zinc-100">Impact Analysis</h4>
                          </div>
                          <p className="text-zinc-300 text-sm">{analysisResult.impact}</p>
                        </div>
                      </div>
  
                      <div className="p-4 bg-zinc-800/50 rounded-lg border border-zinc-800">
                        <h4 className="font-medium text-zinc-100 mb-3">Recommendations</h4>
                        <ul className="space-y-2">
                          {analysisResult.recommendations.map((rec, index) => (
                            <li key={index} className="flex items-start gap-2 text-sm">
                              <lucide.ChevronRight className="h-4 w-4 text-zinc-500 mt-1" />
                              <span className="text-zinc-300">{rec}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          </main>
        </div>
      </div>
    );
  };