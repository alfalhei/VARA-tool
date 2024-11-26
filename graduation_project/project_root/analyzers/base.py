from abc import ABC, abstractmethod
from typing import Dict, List, Optional
from dataclasses import dataclass
from abc import ABC, abstractmethod
from typing import Dict, List, Optional
from dataclasses import dataclass

@dataclass
class VulnerabilitySignature:
    name: str
    patterns: List[str]
    severity: str
    description: str
    impact: str
    cwe_id: str
    cvss_score: float
    remediation: List[str]
    false_positives: List[str]
    references: List[str]

@dataclass
class SecurityAnalysisResult:
    vulnerability_type: str
    severity: str
    confidence: float
    impact: str
    cvss_score: float
    cwe_id: str
    affected_components: List[str]
    evidence: List[str]
    recommendations: List[str]
    references: List[str]
    source: str
    raw_data: Dict[str, Any]

class SecurityAnalyzer(ABC):
    @abstractmethod
    async def analyze(self, content: str) -> Optional[SecurityAnalysisResult]:
        pass

@dataclass
class AnalysisResult:
    vulnerability_type: str
    severity: str
    confidence: float
    impact: str
    recommendations: List[str]
    source: str

class BaseAnalyzer(ABC):
    @abstractmethod
    def analyze(self, text: str) -> Optional[AnalysisResult]:
        pass

    @abstractmethod
    def cleanup(self):
        pass

class VulnerabilityPatterns:
    @staticmethod
    def get_patterns() -> Dict:
        return {
            'SQL Injection': {
                'patterns': [
                    r"(?i)('\s*OR\s*'1'\s*=\s*'1)",
                    r"(?i)('\s*OR\s*1\s*=\s*1\s*--)",
                    r"(?i)(UNION\s+SELECT\s+NULL)",
                ],
                'severity_weights': {
                    'high': ['UNION', 'DROP', 'EXEC'],
                    'medium': ['OR', 'AND', 'SELECT'],
                    'low': ['DECLARE', 'CONVERT', 'CAST']
                }
            },
            'Privilege Escalation': {
                'patterns': [
                    r"(?i)(sudo\s+su\b)",
                    r"(?i)(sudo\s+-s\b)",
                    r"(?i)(/etc/passwd\b)",
                ],
                'severity_weights': {
                    'high': ['sudo su', 'shadow', 'root'],
                    'medium': ['chmod', 'chown'],
                    'low': ['passwd', 'groups']
                }
            }
        }

    @staticmethod
    def get_recommendations(vuln_type: str) -> List[str]:
        recommendations = {
            'SQL Injection': [
                "Implement parameterized queries",
                "Use an ORM framework",
                "Enable WAF rules for SQL injection protection"
            ],
            'Privilege Escalation': [
                "Implement principle of least privilege",
                "Regular audit of sudo access",
                "Monitor system logs for suspicious activities"
            ]
        }
        return recommendations.get(vuln_type, ["Conduct security assessment"])
    @abstractmethod
    def cleanup(self):
        pass