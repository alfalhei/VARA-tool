import re
import logging
from typing import Optional, List, Dict
from .base import BaseAnalyzer, AnalysisResult, VulnerabilityPatterns

logger = logging.getLogger(__name__)
import re
import logging
from typing import Optional, List, Dict
from concurrent.futures import ThreadPoolExecutor
from .base import SecurityAnalyzer, SecurityAnalysisResult
from .vulnerability_db import VulnerabilityDatabase

class EnhancedPatternAnalyzer(SecurityAnalyzer):
    def __init__(self):
        self.signatures = VulnerabilityDatabase.get_signatures()
        self.regex_cache = {}
        self.max_threads = 4
        
    async def analyze(self, content: str) -> Optional[SecurityAnalysisResult]:
        try:
            results = []
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                futures = []
                for vuln_id, signature in self.signatures.items():
                    future = executor.submit(
                        self._analyze_patterns,
                        content,
                        signature
                    )
                    futures.append((vuln_id, future))
                
                for vuln_id, future in futures:
                    result = future.result()
                    if result:
                        results.append(result)
            
            if not results:
                return None
                
            return max(results, key=lambda x: x.confidence)
            
        except Exception as e:
            logger.error(f"Pattern analysis error: {str(e)}")
            return None
    
    def cleanup(self):
        self.regex_cache.clear()
        
class PatternAnalyzer(BaseAnalyzer):
    def __init__(self):
        self.patterns = VulnerabilityPatterns.get_patterns()

    def analyze(self, text: str) -> Optional[AnalysisResult]:
        try:
            results = []
            for vuln_type, config in self.patterns.items():
                matches = []
                for pattern in config['patterns']:
                    found = re.finditer(pattern, text)
                    matches.extend([match.group() for match in found])

                if matches:
                    severity = self._calculate_severity(matches, config['severity_weights'])
                    confidence = len(matches) / len(config['patterns'])
                    
                    results.append({
                        'type': vuln_type,
                        'severity': severity,
                        'confidence': confidence,
                        'matches': len(matches)
                    })

            if not results:
                return None

            best_match = max(results, key=lambda x: x['confidence'])
            
            return AnalysisResult(
                vulnerability_type=best_match['type'],
                severity=best_match['severity'],
                confidence=best_match['confidence'],
                impact=f"Found {best_match['matches']} potential {best_match['type']} patterns",
                recommendations=VulnerabilityPatterns.get_recommendations(best_match['type']),
                source="pattern"
            )
        except Exception as e:
            logger.error(f"Pattern analysis error: {str(e)}")
            return None

    def _calculate_severity(self, matches: List[str], severity_weights: Dict) -> str:
        severity_scores = {'high': 0, 'medium': 0, 'low': 0}
        
        for match in matches:
            for severity, patterns in severity_weights.items():
                if any(pattern.lower() in match.lower() for pattern in patterns):
                    severity_scores[severity] += 1
        
        if severity_scores['high'] > 0:
            return 'Critical' if severity_scores['high'] > 2 else 'High'
        elif severity_scores['medium'] > 0:
            return 'Medium'
        return 'Low'

    def cleanup(self):
        pass