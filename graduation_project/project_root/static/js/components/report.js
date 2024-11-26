import React, { useState } from 'react';
import { 
  Shield, AlertTriangle, CheckCircle, FileText, 
  ChevronDown, ChevronUp, Calendar, Clock, Users,
  Target, Database, Server, Lock, Activity
} from 'lucide-react';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';

const ProfessionalVAPTReport = () => {
  const [expandedSections, setExpandedSections] = useState({
    executive: true,
    scope: true,
    methodology: true,
    preparation: true,
    assessment: true,
    remediation: true,
    findings: true,
    intelligence: true,
    compliance: true
  });

  const toggleSection = (section) => {
    setExpandedSections(prev => ({
      ...prev,
      [section]: !prev[section]
    }));
  };

  // Sample report data - would come from props in production
  const reportData = {
    metadata: {
      reportDate: new Date().toISOString().split('T')[0],
      version: "1.0",
      reference: "VAPT-2024-001",
      organization: "Sample Organization",
      classification: "Confidential",
      reviewDate: "2025-02-01",
      approvers: [
        { role: "Head of Cybersecurity", name: "John Smith", date: "2024-02-01" },
        { role: "IT Director", name: "Jane Doe", date: "2024-02-01" }
      ]
    },
    phases: {
      preparation: {
        completedSteps: [
          { id: "1.1", name: "Process Owner Assignment", status: "Complete" },
          { id: "1.2", name: "Asset Identification", status: "Complete" },
          { id: "1.3", name: "Business Criticality Assessment", status: "Complete" }
        ],
        assetScope: {
          total: 150,
          critical: 45,
          high: 65,
          medium: 25,
          low: 15
        }
      },
      assessment: {
        scanResults: {
          total: 145,
          successful: 142,
          failed: 3,
          excluded: 5
        },
        coverage: "98%",
        duration: "72 hours"
      }
    },
    findings: [
      {
        id: "VUL-001",
        type: "SQL Injection",
        severity: "Critical",
        confidence: 0.95,
        status: "Open",
        impact: "Potential unauthorized database access and data exfiltration",
        affectedAssets: ["web-server-01", "api-gateway"],
        details: "Multiple SQL injection vulnerabilities were discovered in the login and search functionalities",
        recommendations: [
          "Implement parameterized queries",
          "Deploy WAF with SQL injection rules",
          "Implement input validation",
          "Regular security training for developers"
        ],
        timeline: "24-48 hours",
        owner: "Security Team"
      },
      {
        id: "VUL-002",
        type: "Outdated SSL/TLS",
        severity: "High",
        confidence: 0.9,
        status: "In Progress",
        impact: "Potential man-in-the-middle attacks and data interception",
        affectedAssets: ["load-balancer", "reverse-proxy"],
        details: "Several endpoints are using deprecated TLS 1.1 protocol",
        recommendations: [
          "Upgrade to TLS 1.3",
          "Disable older protocols",
          "Implement perfect forward secrecy",
          "Regular SSL/TLS configuration review"
        ],
        timeline: "1 week",
        owner: "Infrastructure Team"
      }
    ],
    compliance: {
      frameworks: ["ECC-1:2018", "DCC-1:2022", "CSCC-1:2019", "CCC-1:2020"],
      status: "Partially Compliant",
      gaps: 3,
      nextReview: "2024-05-01"
    }
  };

  const SeverityBadge = ({ severity }) => {
    const colors = {
      Critical: "bg-red-500/10 text-red-500",
      High: "bg-orange-500/10 text-orange-500",
      Medium: "bg-yellow-500/10 text-yellow-500",
      Low: "bg-green-500/10 text-green-500"
    };

    return (
      <span className={`px-2 py-1 rounded-full text-xs font-medium ${colors[severity]}`}>
        {severity}
      </span>
    );
  };

  const Section = ({ title, icon: Icon, expanded, onToggle, children }) => (
    <div className="mb-6 border border-zinc-800 rounded-lg overflow-hidden">
      <button 
        onClick={onToggle}
        className="w-full flex items-center justify-between p-4 bg-zinc-900 hover:bg-zinc-800 transition-colors"
      >
        <div className="flex items-center gap-2">
          <Icon className="w-5 h-5 text-cyan-500" />
          <h2 className="text-lg font-semibold text-white">{title}</h2>
        </div>
        {expanded ? <ChevronUp className="w-5 h-5" /> : <ChevronDown className="w-5 h-5" />}
      </button>
      {expanded && (
        <div className="p-4 bg-zinc-900/50">
          {children}
        </div>
      )}
    </div>
  );

  return (
    <div className="max-w-5xl mx-auto p-6 bg-zinc-900/50 rounded-xl space-y-6">
      {/* Header */}
      <div className="border-b border-zinc-800 pb-6">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h1 className="text-3xl font-bold text-white">Vulnerability Assessment Report</h1>
            <p className="text-zinc-400">Classification: {reportData.metadata.classification}</p>
          </div>
          <Shield className="w-16 h-16 text-cyan-500" />
        </div>
        
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
          <div>
            <p className="text-zinc-400">Reference</p>
            <p className="text-white">{reportData.metadata.reference}</p>
          </div>
          <div>
            <p className="text-zinc-400">Date</p>
            <p className="text-white">{reportData.metadata.reportDate}</p>
          </div>
          <div>
            <p className="text-zinc-400">Version</p>
            <p className="text-white">{reportData.metadata.version}</p>
          </div>
          <div>
            <p className="text-zinc-400">Next Review</p>
            <p className="text-white">{reportData.metadata.reviewDate}</p>
          </div>
        </div>
      </div>

      {/* Disclaimer */}
      <Alert className="mb-6">
        <AlertTriangle className="w-4 h-4" />
        <AlertTitle>Confidentiality Notice</AlertTitle>
        <AlertDescription>
          This report contains sensitive security information aligned with {reportData.organization}'s 
          security policies and regulatory requirements. Distribution is restricted to authorized personnel only.
        </AlertDescription>
      </Alert>

      {/* Executive Summary */}
      <Section 
        title="Executive Summary" 
        icon={FileText}
        expanded={expandedSections.executive}
        onToggle={() => toggleSection('executive')}
      >
        <div className="space-y-4">
          <p className="text-zinc-300">
            This vulnerability assessment was conducted to evaluate and protect {reportData.organization}'s 
            information technology assets against cybersecurity threats and vulnerabilities.
          </p>
          
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-4">
            <div className="bg-zinc-800/50 p-4 rounded-lg">
              <p className="text-sm text-zinc-400">Total Assets</p>
              <p className="text-2xl font-bold text-white">{reportData.phases.preparation.assetScope.total}</p>
            </div>
            <div className="bg-zinc-800/50 p-4 rounded-lg">
              <p className="text-sm text-zinc-400">Critical Findings</p>
              <p className="text-2xl font-bold text-red-500">
                {reportData.findings.filter(f => f.severity === "Critical").length}
              </p>
            </div>
            <div className="bg-zinc-800/50 p-4 rounded-lg">
              <p className="text-sm text-zinc-400">Scan Coverage</p>
              <p className="text-2xl font-bold text-cyan-500">{reportData.phases.assessment.coverage}</p>
            </div>
            <div className="bg-zinc-800/50 p-4 rounded-lg">
              <p className="text-sm text-zinc-400">Compliance Gaps</p>
              <p className="text-2xl font-bold text-orange-500">{reportData.compliance.gaps}</p>
            </div>
          </div>
        </div>
      </Section>

      {/* Scope & Methodology */}
      <Section 
        title="Scope & Methodology" 
        icon={Target}
        expanded={expandedSections.methodology}
        onToggle={() => toggleSection('methodology')}
      >
        <div className="space-y-4">
          <h3 className="text-lg font-medium text-white mb-2">Assessment Scope</h3>
          <div className="grid grid-cols-2 gap-4">
            <div className="space-y-2">
              <h4 className="text-sm font-medium text-zinc-400">In Scope</h4>
              <ul className="list-disc list-inside text-zinc-300 space-y-1">
                <li>Network infrastructure</li>
                <li>Web applications</li>
                <li>Database servers</li>
                <li>Cloud services</li>
              </ul>
            </div>
            <div className="space-y-2">
              <h4 className="text-sm font-medium text-zinc-400">Out of Scope</h4>
              <ul className="list-disc list-inside text-zinc-300 space-y-1">
                <li>Third-party integrations</li>
                <li>Physical security</li>
                <li>Social engineering</li>
              </ul>
            </div>
          </div>
        </div>
      </Section>

      {/* Detailed Findings */}
      <Section 
        title="Detailed Findings" 
        icon={AlertTriangle}
        expanded={expandedSections.findings}
        onToggle={() => toggleSection('findings')}
      >
        <div className="space-y-6">
          {reportData.findings.map((finding, index) => (
            <div key={finding.id} className="p-4 border border-zinc-800 rounded-lg">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <h3 className="text-lg font-medium text-white">{finding.type}</h3>
                  <span className="text-sm text-zinc-500">({finding.id})</span>
                </div>
                <SeverityBadge severity={finding.severity} />
              </div>
              
              <div className="grid grid-cols-2 gap-4 mb-4">
                <div>
                  <p className="text-sm text-zinc-400">Confidence</p>
                  <p className="text-white">{(finding.confidence * 100).toFixed(0)}%</p>
                </div>
                <div>
                  <p className="text-sm text-zinc-400">Status</p>
                  <p className="text-white">{finding.status}</p>
                </div>
              </div>
              
              <div className="space-y-4">
                <div>
                  <h4 className="text-sm font-medium text-zinc-400 mb-1">Impact</h4>
                  <p className="text-zinc-300">{finding.impact}</p>
                </div>
                
                <div>
                  <h4 className="text-sm font-medium text-zinc-400 mb-1">Affected Assets</h4>
                  <div className="flex flex-wrap gap-2">
                    {finding.affectedAssets.map((asset, i) => (
                      <span key={i} className="px-2 py-1 bg-zinc-800 rounded-full text-xs text-zinc-300">
                        {asset}
                      </span>
                    ))}
                  </div>
                </div>
                
                <div>
                  <h4 className="text-sm font-medium text-zinc-400 mb-1">Recommendations</h4>
                  <ul className="list-disc list-inside text-zinc-300 space-y-1">
                    {finding.recommendations.map((rec, i) => (
                      <li key={i}>{rec}</li>
                    ))}
                  </ul>
                </div>
                
                <div className="grid grid-cols-2 gap-4 mt-4 pt-4 border-t border-zinc-800">
                  <div>
                    <p className="text-sm text-zinc-400">Remediation Timeline</p>
                    <p className="text-white">{finding.timeline}</p>
                  </div>
                  <div>
                    <p className="text-sm text-zinc-400">Owner</p>
                    <p className="text-white">{finding.owner}</p>
                  </div>
                </div>
              </div>
            </div>
          ))}
        </div>
      </Section>

      {/* Compliance Status */}
      <Section 
        title="Compliance Status" 
        icon={CheckCircle}
        expanded={expandedSections.compliance}
        onToggle={() => toggleSection('compliance')}
      >
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <h4 className="text-sm font-medium text-zinc-400 mb-2">Frameworks</h4>
              <ul className="space-y-2">
                {reportData.compliance.frameworks.map((framework, i) => (
                  <li key={i} className="flex items-center gap-2 text-zinc-300">
                    <Lock className="w-4 h-4 text-cyan-500" />
                    {framework}
                  </li>
                ))}
              </ul>
            </div>
            <div>
              <h4 className="text-sm font-medium text-zinc-400 mb-2">Status Overview</h4>
              <div className="space-y-2">
                <p className="text-zinc-300">
                  Current Status: {reportData.compliance.status}
                </p>
                <p className="text-zinc-300">
                  Identified Gaps: {reportData.compliance.gaps}
                </p>
                <p className="text-zinc-300">
                   Next Review: {reportData.compliance.nextReview}
              </p>
              </div>
            </div>
          </div>
        </div>
      </Section>

      {/* Phase 1: Preparation Details */}
      <Section 
        title="Phase 1: Preparation Assessment" 
        icon={Target}
        expanded={expandedSections.preparation}
        onToggle={() => toggleSection('preparation')}
      >
        <div className="space-y-6">
          {/* Completed Steps */}
          <div>
            <h3 className="text-lg font-medium text-white mb-4">Preparation Checklist</h3>
            <div className="grid gap-3">
              {reportData.phases.preparation.completedSteps.map((step, index) => (
                <div key={index} className="flex items-center justify-between p-3 bg-zinc-800/50 rounded-lg">
                  <div className="flex items-center gap-2">
                    <CheckCircle className="w-4 h-4 text-green-500" />
                    <span className="text-zinc-300">{step.id}: {step.name}</span>
                  </div>
                  <span className="text-sm text-green-500">{step.status}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Asset Scope */}
          <div>
            <h3 className="text-lg font-medium text-white mb-4">Asset Criticality Distribution</h3>
            <div className="grid grid-cols-4 gap-4">
              <div className="p-4 bg-red-500/10 rounded-lg">
                <p className="text-red-500 text-sm mb-1">Critical</p>
                <p className="text-2xl font-bold text-white">{reportData.phases.preparation.assetScope.critical}</p>
              </div>
              <div className="p-4 bg-orange-500/10 rounded-lg">
                <p className="text-orange-500 text-sm mb-1">High</p>
                <p className="text-2xl font-bold text-white">{reportData.phases.preparation.assetScope.high}</p>
              </div>
              <div className="p-4 bg-yellow-500/10 rounded-lg">
                <p className="text-yellow-500 text-sm mb-1">Medium</p>
                <p className="text-2xl font-bold text-white">{reportData.phases.preparation.assetScope.medium}</p>
              </div>
              <div className="p-4 bg-green-500/10 rounded-lg">
                <p className="text-green-500 text-sm mb-1">Low</p>
                <p className="text-2xl font-bold text-white">{reportData.phases.preparation.assetScope.low}</p>
              </div>
            </div>
          </div>
        </div>
      </Section>

      {/* Phase 2: Assessment Results */}
      <Section 
        title="Phase 2: Assessment Results" 
        icon={Activity}
        expanded={expandedSections.assessment}
        onToggle={() => toggleSection('assessment')}
      >
        <div className="space-y-6">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="p-4 bg-zinc-800/50 rounded-lg">
              <p className="text-zinc-400 text-sm mb-1">Total Scans</p>
              <p className="text-2xl font-bold text-white">{reportData.phases.assessment.scanResults.total}</p>
            </div>
            <div className="p-4 bg-zinc-800/50 rounded-lg">
              <p className="text-zinc-400 text-sm mb-1">Successful</p>
              <p className="text-2xl font-bold text-green-500">{reportData.phases.assessment.scanResults.successful}</p>
            </div>
            <div className="p-4 bg-zinc-800/50 rounded-lg">
              <p className="text-zinc-400 text-sm mb-1">Failed</p>
              <p className="text-2xl font-bold text-red-500">{reportData.phases.assessment.scanResults.failed}</p>
            </div>
            <div className="p-4 bg-zinc-800/50 rounded-lg">
              <p className="text-zinc-400 text-sm mb-1">Excluded</p>
              <p className="text-2xl font-bold text-yellow-500">{reportData.phases.assessment.scanResults.excluded}</p>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-6">
            <div className="p-4 border border-zinc-800 rounded-lg">
              <h4 className="text-sm font-medium text-zinc-400 mb-2">Scan Coverage</h4>
              <div className="flex items-end gap-2">
                <span className="text-3xl font-bold text-cyan-500">{reportData.phases.assessment.coverage}</span>
                <span className="text-zinc-400">of total assets</span>
              </div>
            </div>
            <div className="p-4 border border-zinc-800 rounded-lg">
              <h4 className="text-sm font-medium text-zinc-400 mb-2">Assessment Duration</h4>
              <div className="flex items-end gap-2">
                <span className="text-3xl font-bold text-cyan-500">{reportData.phases.assessment.duration}</span>
                <span className="text-zinc-400">total time</span>
              </div>
            </div>
          </div>
        </div>
      </Section>

      {/* Phase 3: Remediation Timeline */}
      <Section 
        title="Phase 3: Remediation Timeline" 
        icon={Clock}
        expanded={expandedSections.remediation}
        onToggle={() => toggleSection('remediation')}
      >
        <div className="space-y-4">
          <div className="grid gap-4">
            <div className="p-4 border border-zinc-800 rounded-lg">
              <h4 className="text-white font-medium mb-3">Critical Vulnerabilities</h4>
              <div className="flex items-center justify-between text-sm">
                <span className="text-zinc-300">Required Resolution Time</span>
                <span className="text-red-500 font-medium">24-48 hours</span>
              </div>
            </div>
            <div className="p-4 border border-zinc-800 rounded-lg">
              <h4 className="text-white font-medium mb-3">High Vulnerabilities</h4>
              <div className="flex items-center justify-between text-sm">
                <span className="text-zinc-300">Required Resolution Time</span>
                <span className="text-orange-500 font-medium">1 week</span>
              </div>
            </div>
            <div className="p-4 border border-zinc-800 rounded-lg">
              <h4 className="text-white font-medium mb-3">Medium Vulnerabilities</h4>
              <div className="flex items-center justify-between text-sm">
                <span className="text-zinc-300">Required Resolution Time</span>
                <span className="text-yellow-500 font-medium">1 month</span>
              </div>
            </div>
            <div className="p-4 border border-zinc-800 rounded-lg">
              <h4 className="text-white font-medium mb-3">Low Vulnerabilities</h4>
              <div className="flex items-center justify-between text-sm">
                <span className="text-zinc-300">Required Resolution Time</span>
                <span className="text-green-500 font-medium">3 months</span>
              </div>
            </div>
          </div>
        </div>
      </Section>

      {/* Phase 4: Threat Intelligence */}
      <Section 
        title="Phase 4: Threat Intelligence" 
        icon={Database}
        expanded={expandedSections.intelligence}
        onToggle={() => toggleSection('intelligence')}
      >
        <div className="space-y-4">
          <div className="p-4 bg-zinc-800/50 rounded-lg">
            <h4 className="text-white font-medium mb-3">Threat Feed Sources</h4>
            <ul className="space-y-2 text-zinc-300">
              <li className="flex items-center gap-2">
                <Shield className="w-4 h-4 text-cyan-500" />
                National Cybersecurity Authority (NCA) Feeds
              </li>
              <li className="flex items-center gap-2">
                <Shield className="w-4 h-4 text-cyan-500" />
                Industry-specific threat intelligence
              </li>
              <li className="flex items-center gap-2">
                <Shield className="w-4 h-4 text-cyan-500" />
                Vendor security advisories
              </li>
            </ul>
          </div>
        </div>
      </Section>

      {/* Document Approval */}
      <Section 
        title="Document Approval" 
        icon={Users}
        expanded={expandedSections.approval}
        onToggle={() => toggleSection('approval')}
      >
        <div className="space-y-4">
          {reportData.metadata.approvers.map((approver, index) => (
            <div key={index} className="p-4 border border-zinc-800 rounded-lg">
              <div className="grid grid-cols-3 gap-4">
                <div>
                  <p className="text-sm text-zinc-400">Role</p>
                  <p className="text-white">{approver.role}</p>
                </div>
                <div>
                  <p className="text-sm text-zinc-400">Name</p>
                  <p className="text-white">{approver.name}</p>
                </div>
                <div>
                  <p className="text-sm text-zinc-400">Date</p>
                  <p className="text-white">{approver.date}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </Section>
    </div>
  );
};

export default ProfessionalVAPTReport;