import React, { useState } from 'react';
import { Shield, Upload, RefreshCw, Clock, AlertTriangle, ChevronRight, Terminal, Activity } from 'lucide-react';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { ScrollArea } from '@/components/ui/scroll-area';

// Utility function to merge class names
const mergeClasses = (...classes) => {
  return classes.filter(Boolean).join(' ');
};

const Dashboard = () => {
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const [analysisResult, setAnalysisResult] = useState(null);
  const [error, setError] = useState(null);
  const [selectedSession, setSelectedSession] = useState(null);

  // Mock recent sessions data - replace with real data
  const recentSessions = [
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
  ];

  const handleFileUpload = async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    try {
      setIsAnalyzing(true);
      setError(null);

      const formData = new FormData();
      formData.append('file', file);

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
  const token = document.querySelector('meta[name="csrf-token"]').content;
  fetch('/upload_image', {
      method: 'POST',
      headers: {
          'X-CSRFToken': token
      },
      body: formData,
      credentials: 'same-origin'
  })
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
          <h2 className="text-xl font-semibold text-zinc-100 flex items-center gap-2">
            <Terminal className="h-5 w-5" />
            VAPT Analysis
          </h2>
        </div>
        <ScrollArea className="flex-1">
          <div className="p-4 space-y-2">
            <h3 className="text-sm font-medium text-zinc-400 flex items-center gap-2 mb-4">
              <Clock className="h-4 w-4" />
              Recent Sessions
            </h3>
            {recentSessions.map((session) => (
              <div
                key={session.id}
                onClick={() => setSelectedSession(session)}
                className={mergeClasses(
                  "p-3 rounded-lg cursor-pointer transition-colors",
                  "hover:bg-zinc-800/50",
                  selectedSession?.id === session.id ? "bg-zinc-800" : "bg-zinc-900"
                )}
              >
                <div className="flex items-center justify-between">
                  <span className="text-sm text-zinc-300">{session.vulnerability}</span>
                  <ChevronRight className="h-4 w-4 text-zinc-600" />
                </div>
                <div className="flex items-center justify-between mt-2">
                  <span className="text-xs text-zinc-500">{session.timestamp}</span>
                  <span className={mergeClasses(
                    "text-xs px-2 py-1 rounded",
                    getSeverityBgColor(session.severity),
                    getSeverityColor(session.severity)
                  )}>
                    {session.severity}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </ScrollArea>
      </div>

      {/* Main Content */}
      <div className="flex-1 overflow-auto">
        <div className="p-6 max-w-5xl mx-auto">
          <Card className="bg-zinc-900 border-zinc-800">
            <CardHeader>
              <CardTitle className="text-zinc-100 flex items-center gap-2">
                <Activity className="h-6 w-6" />
                Security Analysis Dashboard
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-6">
                <div className="flex flex-col items-center p-6 border-2 border-dashed border-zinc-800 rounded-lg bg-zinc-900/50 hover:bg-zinc-800/50 transition-colors">
                  <Upload className="h-12 w-12 text-zinc-400 mb-4" />
                  <input
                    type="file"
                    onChange={handleFileUpload}
                    accept="image/*"
                    className="block w-full text-sm text-zinc-400 file:mr-4 file:py-2 file:px-4 file:rounded-full file:border-0 file:text-sm file:font-semibold file:bg-zinc-800 file:text-zinc-100 hover:file:bg-zinc-700"
                  />
                </div>

                {isAnalyzing && (
                  <div className="flex items-center justify-center gap-2 text-zinc-300">
                    <RefreshCw className="h-5 w-5 animate-spin" />
                    Analyzing image...
                  </div>
                )}

                {error && (
                  <Alert variant="destructive" className="bg-red-900/20 border-red-900">
                    <AlertTriangle className="h-4 w-4" />
                    <AlertTitle>Error</AlertTitle>
                    <AlertDescription>{error}</AlertDescription>
                  </Alert>
                )}

                {analysisResult && (
                  <div className="space-y-4">
                    <div className="grid gap-4 md:grid-cols-2">
                      <Card className="bg-zinc-900 border-zinc-800">
                        <CardHeader>
                          <CardTitle className={mergeClasses("flex items-center gap-2", getSeverityColor(analysisResult.severity))}>
                            <Shield className="h-5 w-5" />
                            {analysisResult.vulnerability_type}
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-4">
                          <div className={mergeClasses(
                            "p-4 rounded-lg",
                            getSeverityBgColor(analysisResult.severity)
                          )}>
                            <div className="space-y-2 text-zinc-100">
                              <p><strong>Severity:</strong> {analysisResult.severity}</p>
                              <p><strong>Confidence:</strong> {(analysisResult.confidence * 100).toFixed(1)}%</p>
                              <p><strong>Impact:</strong> {analysisResult.impact}</p>
                            </div>
                          </div>
                        </CardContent>
                      </Card>

                      <Card className="bg-zinc-900 border-zinc-800">
                        <CardHeader>
                          <CardTitle className="text-zinc-100">Recommendations</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <ul className="space-y-2">
                            {analysisResult.recommendations.map((rec, index) => (
                              <li key={index} className="flex items-start gap-2 text-zinc-300">
                                <ChevronRight className="h-4 w-4 mt-1 text-zinc-500" />
                                {rec}
                              </li>
                            ))}
                          </ul>
                        </CardContent>
                      </Card>
                    </div>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;