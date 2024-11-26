import os
import uuid
import json
import logging
from datetime import datetime, timezone
from pathlib import Path
import asyncio
from functools import wraps
from typing import Optional, Dict, List
import io
import re
from sqlalchemy import desc
from sqlalchemy.orm import relationship, foreign
from sqlalchemy import ForeignKey
from sqlalchemy import text, inspect
import logging
from datetime import datetime, timezone
from typing import Optional
from functools import wraps
from dataclasses import dataclass
import aiohttp
from dotenv import load_dotenv
from pathlib import Path
from datetime import datetime, timezone
# Flask imports
from flask import (
    Flask, render_template, request, redirect, url_for, flash, jsonify, 
    send_file, make_response, current_app
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, UserMixin, login_user, login_required, 
    logout_user, current_user
)
from flask_wtf.csrf import CSRFProtect, generate_csrf
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo

# Third-party imports
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from google.cloud import vision
import weasyprint
from dotenv import load_dotenv
import logging
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional
from flask import jsonify, make_response, render_template
from flask_login import login_required, current_user
from weasyprint import HTML, CSS
from weasyprint.text.fonts import FontConfiguration
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional
from flask import jsonify, make_response, render_template
from flask_login import current_user
from weasyprint import HTML, CSS
from weasyprint.text.fonts import FontConfiguration  
from werkzeug.utils import secure_filename


load_dotenv()
# Base setup
BASE_DIR = Path(__file__).resolve().parent
UPLOAD_FOLDER = BASE_DIR / 'uploads'
UPLOAD_FOLDER.mkdir(exist_ok=True)

@dataclass
class SecurityAnalysisResult:
    vulnerability_type: str
    severity: str
    confidence: float
    impact: str
    cvss_score: float
    cwe_id: str
    evidence: List[Dict]
    recommendations: List[str]
    affected_components: List[str]
    references: List[str]
    false_positives: List[Dict]
    attack_vectors: List[Dict]
    raw_response: Optional[str] = None
from sqlalchemy import inspect

import logging
import json
import time
from typing import Dict, List, Optional
from dataclasses import dataclass
from openai import OpenAI
import asyncio

@dataclass
class SecurityAnalysisResult:
    vulnerability_type: str
    severity: str
    confidence: float
    impact: str
    cvss_score: float
    cwe_id: str
    evidence: List[Dict]
    recommendations: List[str]
    affected_components: List[str]
    references: List[str]
    false_positives: List[Dict]
    attack_vectors: List[Dict]
    raw_response: Optional[str] = None

class OpenAIAssistantAnalyzer:
    def __init__(self, api_key: str, assistant_id: str = "asst_2ZsSx8Cvn6k7HX6zZXemEwqK"):  # Updated default ID
        self.client = OpenAI(api_key=api_key)
        self.assistant_id = assistant_id
        self.logger = logging.getLogger(__name__)
        self.max_retries = 3
        self.retry_delay = 2
        self.timeout = 120
        
        try:
            self.assistant = self.client.beta.assistants.retrieve(assistant_id)
            self.logger.info(f"Successfully connected to Assistant: {assistant_id}")
        except Exception as e:
            self.logger.error(f"Failed to retrieve assistant: {e}")
            raise

    async def analyze(self, content: str) -> Optional[SecurityAnalysisResult]:
        """Main analysis method with retry logic."""
        for attempt in range(self.max_retries):
            try:
                thread = await self._create_thread()
                if not thread:
                    self.logger.error(f"Failed to create thread on attempt {attempt + 1}")
                    continue

                # Add message
                message_succeeded = await self.add_message(thread.id, content)
                if not message_succeeded:
                    self.logger.error(f"Failed to add message on attempt {attempt + 1}")
                    continue

                # Run analysis
                run = await self.run_assistant(thread.id)
                if not run:
                    self.logger.error(f"Failed to start run on attempt {attempt + 1}")
                    continue

                # Wait for and process results
                result = await self._wait_for_completion(thread.id, run.id)
                if result:
                    return result

                self.logger.error(f"Analysis attempt {attempt + 1} failed")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay * (2 ** attempt))

            except Exception as e:
                self.logger.error(f"Analysis attempt {attempt + 1} failed with error: {str(e)}")
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay * (2 ** attempt))

        return self.get_default_result()

    async def _create_thread(self):
        """Create a new thread with error handling."""
        try:
            thread = self.client.beta.threads.create()
            self.logger.info(f"Created thread: {thread.id}")
            return thread
        except Exception as e:
            self.logger.error(f"Failed to create thread: {str(e)}")
            return None

    async def add_message(self, thread_id: str, content: str) -> bool:
        """Add message to thread with enhanced instructions for identifying false positives or confirming the absence of vulnerabilities."""
        try:
            message = self.client.beta.threads.messages.create(
                thread_id=thread_id,
                role="user",
                content=f"""Analyze this code/text for ALL security vulnerabilities. The text may contain multiple different vulnerabilities from different files. Identify and list ALL of them.

{content}

Important Instructions:
1. If vulnerabilities are identified, validate each one carefully to minimize the risk of false positives.
2. If you find **no vulnerabilities**, explicitly state this in your response as "No vulnerabilities found."
3. In cases where a vulnerability is flagged, but insufficient evidence exists to confirm it, mark the `confidence` score as low (e.g., below 0.5) and explain the uncertainty in the `evidence` field.

Provide your analysis in this exact JSON format:
{{
    "vulnerability_type": "string - List ALL vulnerabilities found (e.g., 'SQL Injection, Privilege Escalation, RCE' or 'Multiple Vulnerabilities: SQL Injection, Privilege Escalation, RCE'). Use 'None' if no vulnerabilities are found.",
    "severity": "Critical|High|Medium|Low|None",
    "confidence": float between 0-1 (use 0.0 if no vulnerabilities)",
    "impact": "string - Describe the impact of ALL vulnerabilities found, or 'None' if no vulnerabilities are identified",
    "cvss_score": float between 0-10 (use 0.0 if no vulnerabilities)",
    "cwe_id": "Relevant CWE ID(s), or 'None'",
    "evidence": ["Detailed evidence supporting the finding, or an explanation of why no vulnerabilities were found."],
    "recommendations": ["Recommended remediation steps, or 'None' if no vulnerabilities are found."],
    "affected_components": ["List of affected components, or 'None'."],
    "attack_vectors": ["List of possible attack vectors, or 'None'."]
}}

Examples of good `vulnerability_type` responses:
- "SQL Injection, Privilege Escalation, RCE"
- "Multiple Vulnerabilities: SQL Injection, Privilege Escalation"
- Single vulnerability if only one is found: "SQL Injection"
- "None" (if no vulnerabilities are found)

**Your Priority**: Ensure a thorough analysis, flagging ALL vulnerabilities present. If none are found or a potential vulnerability lacks evidence, provide a clear and justified explanation."""
            )
            self.logger.info(f"Added message to thread {thread_id}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to add message: {str(e)}")
            return False

    async def run_assistant(self, thread_id: str):
        """Start assistant run with enhanced instructions for identifying false positives or confirming the absence of vulnerabilities."""
        try:
            run = self.client.beta.threads.runs.create(
                thread_id=thread_id,
                assistant_id=self.assistant_id,
                instructions="""Analyze ALL the code/text for security vulnerabilities following these steps:
                1. Read and thoroughly analyze ALL provided content, including content from all files.
                2. Identify ALL potential security vulnerabilities—do not stop at just one.
                3. Validate ALL flagged vulnerabilities to minimize false positives.
                4. If you find no vulnerabilities, explicitly state "No vulnerabilities found."
                5. When multiple vulnerabilities exist, list them all in the `vulnerability_type` field separated by commas.
                6. Determine the highest severity across all vulnerabilities and provide a detailed explanation.
                7. Identify ALL relevant CWE IDs and include them.
                8. Provide specific evidence for each vulnerability or justify why no vulnerabilities were found.
                9. List ALL affected components.
                10. Suggest remediation steps for ALL identified vulnerabilities.

Important Notes:
- In cases where insufficient evidence exists to confirm a vulnerability, assign a low `confidence` score and explain the uncertainty.
- For every flagged vulnerability, ensure that evidence, impact, and recommendations are detailed and specific.
- Examples of good `vulnerability_type` responses:
    - "SQL Injection, Privilege Escalation, RCE"
    - "Multiple Vulnerabilities: SQL Injection, Privilege Escalation"
    - Single vulnerability if only one is found: "SQL Injection"
    - "None" (if no vulnerabilities are found).

Return results in valid JSON format with all required fields, ensuring completeness, accuracy, and clarity."""
            )
            self.logger.info(f"Started run {run.id} for thread {thread_id}")
            return run
        except Exception as e:
            self.logger.error(f"Failed to start run: {str(e)}")
            return None

    async def _wait_for_completion(self, thread_id: str, run_id: str) -> Optional[SecurityAnalysisResult]:
        start_time = time.time()
        check_interval = 1
        
        while True:
            try:
                if time.time() - start_time > self.timeout:
                    self.logger.error(f"Run {run_id} timed out after {self.timeout} seconds")
                    return None

                run_status = self.client.beta.threads.runs.retrieve(
                    thread_id=thread_id,
                    run_id=run_id
                )
                
                self.logger.info(f"Run status: {run_status.status}")

                if run_status.status == 'completed':
                    messages = self.client.beta.threads.messages.list(
                        thread_id=thread_id,
                        order="desc",
                        limit=1
                    )
                    
                    if not messages.data:
                        self.logger.error("No messages found after completion")
                        return None
                        
                    response = messages.data[0].content[0].text.value
                    self.logger.info("Successfully received analysis response")
                    return self._parse_response(response)

                elif run_status.status in ['failed', 'cancelled', 'expired']:
                    if hasattr(run_status, 'last_error'):
                        self.logger.error(f"Run failed: {run_status.last_error}")
                    return None

                await asyncio.sleep(check_interval)
                
            except Exception as e:
                self.logger.error(f"Error while checking run status: {str(e)}")
                return None

    def _parse_response(self, response: str) -> SecurityAnalysisResult:
        """Parse assistant response with improved handling of multiple vulnerabilities."""
        try:
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            
            if json_start >= 0 and json_end > json_start:
                json_str = response[json_start:json_end]
                try:
                    data = json.loads(json_str)
                except json.JSONDecodeError:
                    self.logger.error("Failed to parse JSON response")
                    data = self._analyze_text_response(response)
            else:
                self.logger.warning("No JSON found in response, analyzing as text")
                data = self._analyze_text_response(response)

            self.logger.info("Successfully parsed analysis response")
            return SecurityAnalysisResult(
                vulnerability_type=data.get('vulnerability_type', 'Unknown'),
                severity=data.get('severity', 'Medium'),
                confidence=float(data.get('confidence', 0.5)),
                impact=data.get('impact', 'Unknown impact'),
                cvss_score=float(data.get('cvss_score', 5.0)),
                cwe_id=data.get('cwe_id', 'CWE-0'),
                evidence=data.get('evidence', []),
                recommendations=data.get('recommendations', ['Implement security best practices']),
                affected_components=data.get('affected_components', []),
                references=data.get('references', []),
                false_positives=data.get('false_positives', []),
                attack_vectors=data.get('attack_vectors', []),
                raw_response=response
            )
        except Exception as e:
            self.logger.error(f"Response parsing error: {str(e)}")
            return self.get_default_result()

    def get_default_result(self) -> SecurityAnalysisResult:
        """Return default result when analysis fails."""
        return SecurityAnalysisResult(
            vulnerability_type='Unknown',
            severity='Low',
            confidence=0.5,
            impact='Analysis failed to complete',
            cvss_score=0.0,
            cwe_id='CWE-0',
            evidence=[],
            recommendations=['Conduct manual security review'],
            affected_components=[],
            references=[],
            false_positives=[],
            attack_vectors=[],
            raw_response=None
        )

    def cleanup(self):
        """Cleanup any resources."""
        try:
            pass
        except Exception as e:
            self.logger.error(f"Cleanup error: {str(e)}")
class MultiFileProcessor:
    def __init__(self, security_analyzer):
        self.security_analyzer = security_analyzer
        self.logger = logging.getLogger(__name__)

    async def process_files(self, files, user, session_id):
        """
        Process multiple files and perform combined analysis with vulnerability aggregation.
        """
        try:
            file_results = []
            combined_text = []
            filenames = []
            individual_analyses = []
            
            # First pass: Save files, extract text, and analyze individually
            for file in files:
                if not file or not allowed_file(file.filename):
                    continue

                filename = secure_filename(file.filename)
                filenames.append(filename)

                # Save file
                file_path = save_file(user.username, session_id, file)
                if not file_path:
                    continue

                # Extract text based on file type
                try:
                    extracted_text = None
                    if file_path.lower().endswith('.txt'):
                        with open(file_path, 'r', encoding='utf-8') as f:
                            extracted_text = f.read().strip()
                    else:
                        extracted_text = extract_text_with_google_vision(file_path)
                        if extracted_text:
                            extracted_text = extracted_text.strip()

                    if extracted_text:
                        # to combined text
                        combined_text.append(f"=== Content from {filename} ===\n{extracted_text}\n")
                        
                        # Perform individual analysis
                        individual_result = await self.security_analyzer.analyze(extracted_text)
                        if individual_result:
                            individual_analyses.append(individual_result)
                            
                        file_results.append({
                            'filename': filename,
                            'file_path': file_path,
                            'extracted_text': extracted_text,
                            'analysis': individual_result
                        })

                except Exception as e:
                    self.logger.error(f"Error processing {filename}: {str(e)}")
                    continue

            if not file_results:
                return None

            # Combine all extracted text
            unified_text = "\n".join(combined_text)
            
            # Analyze the combined text as well
            combined_analysis = await self.security_analyzer.analyze(unified_text)

            # Aggregate results from individual analyses and combined analysis
            all_vulnerabilities = set()
            all_evidence = []
            all_recommendations = set()
            all_affected_components = set()
            highest_severity = 'Low'
            max_cvss = 0.0
            total_confidence = 0.0
            all_impacts = set()
            all_attack_vectors = []
            
            severity_order = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}

            # Process individual results
            for result in individual_analyses:
                if result.vulnerability_type:
                    all_vulnerabilities.add(result.vulnerability_type)
                if result.evidence:
                    all_evidence.extend(result.evidence)
                if result.recommendations:
                    all_recommendations.update(result.recommendations)
                if result.affected_components:
                    all_affected_components.update(result.affected_components)
                if result.impact:
                    all_impacts.add(result.impact)
                if result.attack_vectors:
                    all_attack_vectors.extend(result.attack_vectors)
                
                # Updated highest severity
                current_severity = severity_order.get(result.severity, 0)
                if current_severity > severity_order.get(highest_severity, 0):
                    highest_severity = result.severity
                
                # Updated max CVSS score
                if result.cvss_score > max_cvss:
                    max_cvss = result.cvss_score
                
                total_confidence += result.confidence

            # combined analysis results if available
            if combined_analysis:
                if combined_analysis.vulnerability_type:
                    all_vulnerabilities.add(combined_analysis.vulnerability_type)
                if combined_analysis.evidence:
                    all_evidence.extend(combined_analysis.evidence)
                if combined_analysis.recommendations:
                    all_recommendations.update(combined_analysis.recommendations)
                if combined_analysis.affected_components:
                    all_affected_components.update(combined_analysis.affected_components)
                if combined_analysis.impact:
                    all_impacts.add(combined_analysis.impact)
                if combined_analysis.attack_vectors:
                    all_attack_vectors.extend(combined_analysis.attack_vectors)

            # Calculate average confidence
            avg_confidence = total_confidence / (len(individual_analyses) + 1) if individual_analyses else 0.5

            # Format vulnerability types for display
            vuln_types = sorted(all_vulnerabilities)
            if len(vuln_types) > 1:
                vulnerability_type = f"Multiple Vulnerabilities: {', '.join(vuln_types)}"
            else:
                vulnerability_type = next(iter(vuln_types)) if vuln_types else "Unknown"

            # Create the aggregated analysis record
            analysis = Analysis(
                session_id=session_id,
                image_path=", ".join(f['file_path'] for f in file_results),
                extracted_text=unified_text,
                vulnerability_type=vulnerability_type,
                severity=highest_severity,
                confidence=avg_confidence,
                impact="Multiple security impacts detected:\n" + "\n".join(all_impacts) if len(all_impacts) > 1 
                       else next(iter(all_impacts)) if all_impacts else "Impact unknown",
                cwe_id="Multiple",  # multiple CWEs
                cvss_score=max_cvss,
                evidence=json.dumps(all_evidence),
                recommendations=json.dumps(list(all_recommendations)),
                affected_components=json.dumps(list(all_affected_components)),
                false_positives=json.dumps([]),
                attack_vectors=json.dumps(all_attack_vectors),
                analysis_sources=json.dumps({
                    'pattern': True,
                    'ml': True,
                    'lora': True,
                    'files_analyzed': filenames,
                    'total_files': len(filenames),
                    'individual_analyses': [
                        {
                            'filename': f['filename'],
                            'vulnerability_type': f['analysis'].vulnerability_type if f['analysis'] else 'Unknown',
                            'severity': f['analysis'].severity if f['analysis'] else 'Low'
                        } for f in file_results if 'analysis' in f
                    ]
                })
            )

            new_session = AnalysisSession(
                user_id=user.id,
                filename=", ".join(filenames),
                status='completed'
            )

            return {
                'session': new_session,
                'analysis': analysis,
                'file_results': file_results,
                'vulnerability_details': {
                    'types': list(all_vulnerabilities),
                    'highest_severity': highest_severity,
                    'total_files': len(filenames)
                }
            }

        except Exception as e:
            self.logger.error(f"Error processing files: {str(e)}")
            return None       
class Config:
    load_dotenv()
    # Basic Flask config
    SECRET_KEY = os.environ.get('SECRET_KEY', 'your-secret-key-here')
    
    # OpenAI config
    OPENAI_API_KEY = os.getenv('OPENAI_API_KEY')
    if not OPENAI_API_KEY:
        raise ValueError("OPENAI_API_KEY environment variable is not set. Check your .env file.")
    
    OPENAI_ASSISTANT_ID = os.getenv('OPENAI_ASSISTANT_ID', 'asst_Du28dWxzx3TU5XQuHyTh2fsl')
    OPENAI_MODEL = os.getenv('OPENAI_MODEL', 'gpt-4o-mini')
    
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{BASE_DIR}/instance/vapt.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    UPLOAD_FOLDER = str(UPLOAD_FOLDER)
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'txt', 'pdf'}
    WTF_CSRF_ENABLED = False
    GOOGLE_CREDENTIALS = str(BASE_DIR / '/Users/sa/Desktop/VARA/avian-sandbox-424508-u3-2dd8eff25585.json')

# Initialize Security Analyzer with proper error handling
def init_security_analyzer():
    try:
        api_key = os.getenv('OPENAI_API_KEY')
        if not api_key:
            raise ValueError("OpenAI API key not found in environment variables")
            
        return OpenAIAssistantAnalyzer(
            api_key=api_key,
            assistant_id=os.getenv('OPENAI_ASSISTANT_ID', 'asst_WTECGEGWiy8gpyZnlPRAlVT2')
        )
    except Exception as e:
        logger.error(f"Failed to initialize OpenAI Assistant: {str(e)}")
        raise
    
# the analyzer initialization
security_analyzer = init_security_analyzer()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(str(BASE_DIR / 'logs' / 'app.log'))
    ]
)
logger = logging.getLogger(__name__)
# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)
# Flask app configuration
app.config['STATIC_FOLDER'] = app.config['UPLOAD_FOLDER']
# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager(app)
#csrf = CSRFProtect(app)
login_manager.login_view = 'login'

# Initialize Google Cloud Vision
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = app.config['GOOGLE_CREDENTIALS']
vision_client = vision.ImageAnnotatorClient()

# Initialize Security Analyzer
security_analyzer = OpenAIAssistantAnalyzer(
    api_key=os.getenv('OPENAI_API_KEY'),
    assistant_id=os.getenv('OPENAI_ASSISTANT_ID')
)

# Database Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Use string references for relationships
    sessions = db.relationship('Session', backref='user', lazy=True)
    analysis_sessions = db.relationship('AnalysisSession', backref='user', lazy=True)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def __repr__(self):
        return f'<User {self.username}>'

class Session(db.Model):
    __tablename__ = 'sessions'
    
    id = db.Column(db.String(36), primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    company_name = db.Column(db.String(255)) 
    created_at = db.Column(db.DateTime, default=datetime.now(timezone.utc))
    status = db.Column(db.String(50), default='active')  # Add status field

    # string reference for relationship
    analyses = db.relationship(
        'Analysis',
        backref='session',
        lazy=True,
        cascade='all, delete-orphan',
        order_by="desc(Analysis.created_at)"  # This ensures latest analysis first
    )

    def __repr__(self):
        return f'<Session {self.id} - {self.company_name}>'


    @property
    def latest_analysis(self):
        """Get the most recent analysis for this session."""
        return self.analyses[0] if self.analyses else None
    
class AnalysisSession(db.Model):
    __tablename__ = 'analysis_sessions'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Use string reference for relationship
    analyses = db.relationship(
        'Analysis',
        backref='analysis_session',
        lazy=True,
        cascade='all, delete-orphan'
    )

class Analysis(db.Model):
    __tablename__ = 'analyses'
    
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(36), db.ForeignKey('sessions.id'), nullable=False)
    analysis_session_id = db.Column(db.Integer, db.ForeignKey('analysis_sessions.id'), nullable=True)
    image_path = db.Column(db.Text)
    extracted_text = db.Column(db.Text)
    vulnerability_type = db.Column(db.String(100))
    severity = db.Column(db.String(50))
    confidence = db.Column(db.Float)
    impact = db.Column(db.Text)
    cwe_id = db.Column(db.String(20))
    cvss_score = db.Column(db.Float)
    evidence = db.Column(db.JSON)
    recommendations = db.Column(db.JSON)
    affected_components = db.Column(db.JSON)
    references = db.Column(db.JSON)
    false_positives = db.Column(db.JSON)
    attack_vectors = db.Column(db.JSON)
    file_info = db.Column(db.JSON)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    device_info = db.Column(db.JSON, nullable=True)
    network_info = db.Column(db.JSON, nullable=True)
    scope_info = db.Column(db.JSON, nullable=True)
    target_info = db.Column(db.JSON, nullable=True)
    
    def __repr__(self):
        return f'<Analysis {self.id}>'
    
    @property
    def safe_recommendations(self):
        """Safely get recommendations as a list."""
        try:
            if self.recommendations:
                return json.loads(self.recommendations)
        except json.JSONDecodeError:
            pass
        return []

    @property
    def safe_evidence(self):
        """Safely get evidence as a list."""
        try:
            if self.evidence:
                return json.loads(self.evidence)
        except json.JSONDecodeError:
            pass
        return []

    @property
    def safe_affected_components(self):
        """Safely get affected components as a list."""
        try:
            if self.affected_components:
                return json.loads(self.affected_components)
        except json.JSONDecodeError:
            pass
        return []

    def to_dict(self):
        """Convert analysis to dictionary format."""
        return {
            'vulnerability_type': self.vulnerability_type or 'Unknown',
            'severity': self.severity or 'Low',
            'confidence': float(self.confidence or 0.5),
            'impact': self.impact or 'No impact information available',
            'cwe_id': self.cwe_id or 'N/A',
            'cvss_score': float(self.cvss_score or 0.0),
            'recommendations': self.safe_recommendations,
            'evidence': self.safe_evidence,
            'affected_components': self.safe_affected_components,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }

    @classmethod
    def get_latest_for_session(cls, session_id):
        """Get the latest analysis for a session."""
        from sqlalchemy import desc
        return cls.query.filter_by(
            session_id=session_id
        ).order_by(desc(cls.created_at)).first()

    def get_image_paths(self):
        """Helper method to safely get image paths"""
        try:
            if self.image_path:
                return json.loads(self.image_path)
            return []
        except:
            return []

    def get_file_info(self):
        """Helper method to safely get file information"""
        try:
            if self.file_info:
                return json.loads(self.file_info)
            return None
        except:
            return None
    def get_device_info(self):
        """Get device information as dictionary."""
        if self.device_info:
            return json.loads(self.device_info)
        return {}
    
    def get_network_info(self):
        """Get network information as dictionary."""
        if self.network_info:
            return json.loads(self.network_info)
        return {}
        
    def get_scope_info(self):
        """Get scope information as dictionary."""
        if self.scope_info:
            return json.loads(self.scope_info)
        return {}
        
    def get_target_info(self):
        """Get target information as dictionary."""
        if self.target_info:
            return json.loads(self.target_info)
        return {}

def perform_database_migration():
    with app.app_context():
        try:
            inspector = inspect(db.engine)
            
            # Check and add new columns
            new_columns = {
                'device_info': 'JSON',
                'network_info': 'JSON',
                'scope_info': 'JSON',
                'target_info': 'JSON'
            }
            
            existing_columns = [c['name'] for c in inspector.get_columns('analyses')]
            
            for column_name, column_type in new_columns.items():
                if column_name not in existing_columns:
                    sql = text(f'ALTER TABLE analyses ADD COLUMN {column_name} {column_type}')
                    db.session.execute(sql)
                    logger.info(f"Successfully added {column_name} column")
            
            db.session.commit()
            logger.info("Database migration completed successfully")
            
        except Exception as e:
            logger.error(f"Migration error: {str(e)}")
            db.session.rollback()
            raise
def async_to_sync(func):
    """
    Decorator to run async functions in sync context.
    Use this to wrap async route handlers in Flask.
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(func(*args, **kwargs))
        finally:
            loop.close()
    return wrapper

#  upload_image route 
@app.route('/upload_image', methods=['POST'])
@login_required
@async_to_sync
async def upload_image():
    try:
        # Debug log the entire request
        logger.info("Request method: %s", request.method)
        logger.info("Request files: %s", request.files)
        logger.info("Request form: %s", request.form)
        
        if 'files[]' not in request.files:
            logger.error("No files[] in request.files. Keys present: %s", list(request.files.keys()))
            return jsonify({'error': 'No files found in request. Please select files to upload.'}), 400

        files = request.files.getlist('files[]')
        logger.info("Number of files received: %d", len(files))
        
        company_name = request.form.get('company_name', '')
        logger.info("Company name: %s", company_name)

        if not files or not any(file.filename for file in files):
            logger.error("No valid files found in request")
            return jsonify({'error': 'No valid files selected'}), 400

        # Create session
        session_id = str(uuid.uuid4())
        logger.info(f"Creating session {session_id} for user {current_user.id}")
        
        new_session = Session(
            id=session_id,
            user_id=current_user.id,
            company_name=company_name,
            status='active'
        )
        
        try:
            db.session.add(new_session)
            db.session.flush()  # Test the database insertion
        except Exception as db_err:
            logger.error(f"Database error creating session: {str(db_err)}")
            db.session.rollback()
            return jsonify({'error': 'Database error while creating session'}), 500

        # Process files
        processed_files = []
        extracted_texts = []

        for file in files:
            if not file or not file.filename:
                logger.warning("Skipping file with no filename")
                continue

            if not allowed_file(file.filename):
                logger.warning(f"File type not allowed: {file.filename}")
                continue

            try:
                # Create user upload directory
                user_upload_dir = os.path.join(
                    current_app.config['UPLOAD_FOLDER'],
                    str(current_user.id),
                    session_id
                )
                os.makedirs(user_upload_dir, exist_ok=True)
                logger.info(f"Created upload directory: {user_upload_dir}")

                # Save file
                filename = secure_filename(file.filename)
                file_path = os.path.join(user_upload_dir, filename)
                file.save(file_path)
                logger.info(f"Saved file to: {file_path}")
                
                # Extract text
                try:
                    if file_path.lower().endswith('.txt'):
                        with open(file_path, 'r', encoding='utf-8') as f:
                            text = f.read().strip()
                        logger.info("Successfully read text file")
                    else:
                        logger.info("Attempting to extract text with Google Vision")
                        text = extract_text_with_google_vision(file_path)
                        logger.info("Successfully extracted text with Google Vision")

                    if text:
                        extracted_texts.append(f"=== Content from {filename} ===\n{text}")
                        processed_files.append({
                            'filename': filename,
                            'path': file_path
                        })
                        logger.info(f"Successfully processed file: {filename}")
                    else:
                        logger.warning(f"No text extracted from file: {filename}")

                except Exception as extract_err:
                    logger.error(f"Text extraction error for {filename}: {str(extract_err)}")
                    continue

            except Exception as file_err:
                logger.error(f"File processing error for {file.filename}: {str(file_err)}")
                continue

        if not processed_files:
            logger.error("No files were successfully processed")
            db.session.rollback()
            return jsonify({'error': 'Could not process any of the uploaded files'}), 400

        # Combine texts
        combined_text = "\n\n".join(extracted_texts)
        logger.info("Combined text length: %d characters", len(combined_text))

        try:
            # Analyze content
            logger.info("Starting security analysis")
            analysis_result = await security_analyzer.analyze(combined_text)
            if not analysis_result:
                logger.error("Security analysis returned None")
                db.session.rollback()
                return jsonify({'error': 'Security analysis failed'}), 500
            logger.info("Security analysis completed successfully")

        except Exception as analysis_err:
            logger.error(f"Security analysis error: {str(analysis_err)}")
            db.session.rollback()
            return jsonify({'error': 'Error during security analysis'}), 500

        try:
            # Create analysis record
            analysis = Analysis(
                session_id=session_id,
                image_path=json.dumps([f['path'] for f in processed_files]),
                extracted_text=combined_text,
                vulnerability_type=analysis_result.vulnerability_type,
                severity=analysis_result.severity,
                confidence=analysis_result.confidence,
                impact=analysis_result.impact,
                cwe_id=analysis_result.cwe_id,
                cvss_score=analysis_result.cvss_score,
                evidence=json.dumps(analysis_result.evidence or []),
                recommendations=json.dumps(analysis_result.recommendations or []),
                affected_components=json.dumps(analysis_result.affected_components or []),
                references=json.dumps(analysis_result.references or []),
                false_positives=json.dumps([]),
                attack_vectors=json.dumps(analysis_result.attack_vectors or []),
                file_info=json.dumps({
                    'files': [f['filename'] for f in processed_files],
                    'total_files': len(processed_files)
                })
            )
            
            db.session.add(analysis)
            db.session.commit()
            logger.info(f"Successfully saved session and analysis. Session ID: {session_id}")

        except Exception as db_err:
            logger.error(f"Database error saving analysis: {str(db_err)}")
            db.session.rollback()
            return jsonify({'error': 'Failed to save analysis results to database'}), 500

        # Prepare success response
        response_data = {
            'success': True,
            'session_id': session_id,
            'company_name': company_name,
            'analysis': {
                'vulnerability_type': analysis_result.vulnerability_type,
                'severity': analysis_result.severity,
                'confidence': analysis_result.confidence,
                'impact': analysis_result.impact,
                'cwe_id': analysis_result.cwe_id,
                'cvss_score': analysis_result.cvss_score,
                'evidence': analysis_result.evidence,
                'recommendations': analysis_result.recommendations,
                'affected_components': analysis_result.affected_components,
                'file_info': {
                    'files': [f['filename'] for f in processed_files],
                    'total_files': len(processed_files)
                }
            }
        }
        
        logger.info("Successfully prepared response")
        return jsonify(response_data)

    except Exception as e:
        logger.error(f"Unexpected upload error: {str(e)}", exc_info=True)
        db.session.rollback()
        return jsonify({
            'error': f'An unexpected error occurred: {str(e)}'
        }), 500
def get_internal_ips():
    """Get internal IP addresses of the system."""
    try:
        import socket
        import netifaces
        
        internal_ips = []
        for interface in netifaces.interfaces():
            try:
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        ip = addr['addr']
                        if not ip.startswith('127.'):  # Exclude localhost
                            internal_ips.append({
                                'ip': ip,
                                'interface': interface,
                                'netmask': addr.get('netmask', 'Unknown')
                            })
            except Exception as e:
                logger.warning(f"Error getting addresses for interface {interface}: {str(e)}")
                
        return internal_ips
    except ImportError:
        return ['Netifaces library not available']
    except Exception as e:
        logger.error(f"Error getting internal IPs: {str(e)}")
        return []

async def get_external_ip():
    """Get external IP address using multiple services."""
    ip_services = [
        'https://api.ipify.org',
        'https://icanhazip.com',
        'https://ifconfig.me/ip'
    ]
    
    try:
        for service in ip_services:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(service, timeout=5) as response:
                        if response.status == 200:
                            return await response.text()
            except:
                continue
        return 'Unable to determine'
    except Exception as e:
        logger.error(f"Error getting external IP: {str(e)}")
        return 'Error getting external IP'

def get_network_interfaces():
    """Get detailed network interface information."""
    try:
        import netifaces
        interfaces = []
        
        for iface in netifaces.interfaces():
            try:
                addrs = netifaces.ifaddresses(iface)
                if netifaces.AF_INET in addrs:
                    for addr in addrs[netifaces.AF_INET]:
                        interfaces.append({
                            'name': iface,
                            'ip': addr.get('addr', 'Unknown'),
                            'netmask': addr.get('netmask', 'Unknown'),
                            'broadcast': addr.get('broadcast', 'Unknown')
                        })
            except Exception as e:
                logger.warning(f"Error getting info for interface {iface}: {str(e)}")
                
        return interfaces
    except ImportError:
        return ['Netifaces library not available']
    except Exception as e:
        logger.error(f"Error getting network interfaces: {str(e)}")
        return []

def get_dns_servers():
    """Get DNS server information."""
    try:
        import dns.resolver
        
        dns_servers = []
        resolver = dns.resolver.Resolver()
        
        # Get nameservers
        for ns in resolver.nameservers:
            dns_servers.append({
                'ip': ns,
                'type': 'nameserver'
            })
            
        return dns_servers
    except ImportError:
        return ['DNS resolver library not available']
    except Exception as e:
        logger.error(f"Error getting DNS servers: {str(e)}")
        return []

def get_network_usage():
    """Get current network usage statistics."""
    try:
        import psutil
        
        net_io = psutil.net_io_counters()
        return {
            'bytes_sent': net_io.bytes_sent,
            'bytes_recv': net_io.bytes_recv,
            'packets_sent': net_io.packets_sent,
            'packets_recv': net_io.packets_recv,
            'errin': net_io.errin,
            'errout': net_io.errout,
            'dropin': net_io.dropin,
            'dropout': net_io.dropout
        }
    except Exception as e:
        logger.error(f"Error getting network usage: {str(e)}")
        return {}

def determine_criticality(severity: str) -> str:
    """Determine system criticality based on highest severity."""
    severity_mapping = {
        'Critical': 'Mission Critical',
        'High': 'Business Critical',
        'Medium': 'Important',
        'Low': 'Normal'
    }
    return severity_mapping.get(severity, 'Normal')

def determine_business_impact(cvss_score: float) -> str:
    """Determine business impact based on CVSS score."""
    if cvss_score >= 9.0:
        return 'Critical Business Impact'
    elif cvss_score >= 7.0:
        return 'Significant Business Impact'
    elif cvss_score >= 4.0:
        return 'Moderate Business Impact'
    return 'Low Business Impact'

def get_file_types(session) -> Dict[str, int]:
    """Get distribution of file types analyzed."""
    file_types = {}
    if hasattr(session, 'files'):
        for file in session.files:
            ext = os.path.splitext(file.filename)[1].lower()
            file_types[ext] = file_types.get(ext, 0) + 1
    return file_types

# Additional helper functions for the report
def identify_entry_points(analysis_data: Dict) -> List[Dict]:
    """Identify potential entry points from analysis data."""
    entry_points = []
    
    if analysis_data.get('extracted_text'):
        # Look for URLs
        urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+', analysis_data['extracted_text'])
        for url in urls:
            entry_points.append({
                'type': 'URL',
                'value': url,
                'risk_level': 'Medium',
                'description': 'Exposed web endpoint'
            })
            
        # Look for ports
        ports = re.findall(r'port (\d+)', analysis_data['extracted_text'], re.IGNORECASE)
        for port in ports:
            entry_points.append({
                'type': 'Port',
                'value': port,
                'risk_level': 'High' if int(port) in [22, 3389, 445] else 'Medium',
                'description': f'Open port {port}'
            })
            
    return entry_points

def identify_vulnerable_dependencies(analysis_data: Dict) -> List[Dict]:
    """Identify vulnerable dependencies from analysis."""
    dependencies = []
    
    if analysis_data.get('affected_components'):
        for component in analysis_data['affected_components']:
            dependencies.append({
                'name': component,
                'version': 'Unknown',
                'vulnerability_type': analysis_data.get('vulnerability_type', 'Unknown'),
                'severity': analysis_data.get('severity', 'Medium'),
                'recommendation': 'Update to latest secure version'
            })
            
    return dependencies

def identify_exposure_points(analysis_data: Dict) -> List[Dict]:
    """Identify potential exposure points."""
    exposure_points = []
    
    #  identified exposure points from the analysis
    if analysis_data.get('evidence'):
        for evidence in analysis_data['evidence']:
            exposure_points.append({
                'type': 'Evidence-based',
                'location': evidence.get('location', 'Unknown'),
                'description': evidence.get('description', ''),
                'severity': evidence.get('severity', 'Medium')
            })
            
    return exposure_points    
@app.route('/api/sessions')
@login_required
def get_sessions():
    try:
        # Get only active sessions with their latest analysis
        sessions = (
            Session.query
            .filter_by(user_id=current_user.id, status='active')
            .order_by(Session.created_at.desc())
            .all()
        )
        
        return jsonify({
            'success': True,
            'sessions': [{
                'id': session.id,
                'company_name': session.company_name,
                'created_at': session.created_at.isoformat(),
                'analysis': {
                    'vulnerability_type': session.latest_analysis.vulnerability_type if session.latest_analysis else 'Unknown',
                    'severity': session.latest_analysis.severity if session.latest_analysis else 'Unknown',
                    'confidence': float(session.latest_analysis.confidence or 0.5) if session.latest_analysis else 0.0
                } if session.latest_analysis else None
            } for session in sessions]
        })
    except Exception as e:
        logger.error(f"Error fetching sessions: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to fetch sessions'
        }), 500
        
@app.route('/api/debug/session/<session_id>')
@login_required
def debug_session(session_id):
    session = Session.query.filter_by(id=session_id, user_id=current_user.id).first()
    if not session:
        return jsonify({'error': 'Session not found'})
        
    analysis = Analysis.query.filter_by(session_id=session_id).first()
    if not analysis:
        return jsonify({'error': 'No analysis found'})
        
    return jsonify({
        'session': {
            'id': session.id,
            'user_id': session.user_id,
            'company_name': session.company_name,
            'created_at': session.created_at.isoformat()
        },
        'analysis': {
            'id': analysis.id,
            'vulnerability_type': analysis.vulnerability_type,
            'severity': analysis.severity,
            'created_at': analysis.created_at.isoformat()
        }
    })
    
def debug_database():
    with app.app_context():
        print("\nChecking Sessions...")
        sessions = Session.query.all()
        for session in sessions:
            print(f"\nSession {session.id}:")
            print(f"User: {session.user_id}")
            print(f"Created: {session.created_at}")
            print(f"Analyses count: {len(session.analyses)}")
            
            for analysis in session.analyses:
                print(f"\n  Analysis {analysis.id}:")
                print(f"  Type: {analysis.vulnerability_type}")
                print(f"  Severity: {analysis.severity}")
class SessionAnalysis(db.Model):
    __tablename__ = 'session_analyses'
    
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(36), db.ForeignKey('sessions.id'), nullable=False)
    vulnerability_type = db.Column(db.String(100))
    severity = db.Column(db.String(50))
    confidence = db.Column(db.Float)
    impact = db.Column(db.Text)
    cwe_id = db.Column(db.String(20))
    cvss_score = db.Column(db.Float)
    evidence = db.Column(db.JSON)
    recommendations = db.Column(db.JSON)
    affected_components = db.Column(db.JSON)
    extracted_text = db.Column(db.Text)  # Add this field
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    extracted_text = db.Column(db.Text)
    attack_vectors = db.Column(db.JSON)
    technical_findings = db.Column(db.Text)

    def __repr__(self):
        return f'<Analysis {self.id}>'
# Forms
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[
        DataRequired(),
        Length(min=4, max=20, message="Username must be between 4 and 20 characters")
    ])
    password = PasswordField('Password', validators=[
        DataRequired(),
        Length(min=6, message="Password must be at least 6 characters")
    ])
    confirm_password = PasswordField('Confirm Password', validators=[
        DataRequired(),
        EqualTo('password', message='Passwords must match')
    ])
    submit = SubmitField('Register')

# Utility Functions
def allowed_file(filename: str) -> bool:
    """
    Check if the file type is allowed.
    
    Args:
        filename: The name of the file to check
        
    Returns:
        bool: True if file type is allowed, False otherwise
    """
    if not filename:
        return False
        
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in current_app.config['ALLOWED_EXTENSIONS']

def save_file(username: str, session_id: str, file) -> Optional[str]:
    """
    Save uploaded file with improved error handling and security checks.
    
    Args:
        username: The username of the uploader
        session_id: The current session ID
        file: The file object from request.files
        
    Returns:
        Optional[str]: The saved file path or None if save failed
    """
    try:
        if not file or not file.filename:
            logger.warning("Invalid file object or empty filename")
            return None
            
        if not allowed_file(file.filename):
            logger.warning(f"File type not allowed: {file.filename}")
            return None
            
        # Create a secure filename
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_filename = f"{timestamp}_{filename}"
        
        # Create user upload directory
        user_upload_dir = os.path.join(
            current_app.config['UPLOAD_FOLDER'],
            username,
            session_id
        )
        os.makedirs(user_upload_dir, exist_ok=True)
        
        # Full path for the file
        file_path = os.path.join(user_upload_dir, safe_filename)
        
        # Save the file
        file.save(file_path)
        logger.info(f"File saved successfully: {file_path}")
        
        return file_path
        
    except Exception as e:
        logger.error(f"Error saving file {file.filename}: {str(e)}")
        return None

def extract_text_with_google_vision(file_path_or_files, session_id=None, username=None):
    """
    Extract text from file(s) using Google Vision API.
    Processes ALL files without stopping.
    """
    # For single file
    if isinstance(file_path_or_files, str):
        try:
            with io.open(file_path_or_files, 'rb') as image_file:
                content = image_file.read()

            image = vision.Image(content=content)
            response = vision_client.text_detection(image=image)
            
            if response.error.message:
                logger.error(f"Google Vision API error: {response.error.message}")
                return None
                
            if response.text_annotations:
                return response.text_annotations[0].description.strip()
            
            logger.warning("No text detected in image")
            return None
            
        except Exception as e:
            logger.error(f"Error extracting text from image: {str(e)}")
            return None
            
    # For multiple files
    else:
        extracted_text = []
        file_paths = []
        filenames = []
        processed_count = 0
        total_files = len(file_path_or_files)

        logger.info(f"Starting to process {total_files} files")

        # Process each file
        for file in file_path_or_files:
            try:
                if not file or not file.filename:
                    logger.warning("Skipping invalid file")
                    continue

                if not allowed_file(file.filename):
                    logger.warning(f"Skipping file with unsupported type: {file.filename}")
                    continue

                filename = secure_filename(file.filename)
                logger.info(f"Processing file {processed_count + 1}/{total_files}: {filename}")

                # Save file
                file_path = save_file(username, session_id, file)
                if not file_path:
                    logger.error(f"Failed to save file: {filename}")
                    continue
                
                file_paths.append(file_path)
                filenames.append(filename)

                # Extract text based on file type
                current_text = None
                
                if file_path.lower().endswith('.txt'):
                    with open(file_path, 'r', encoding='utf-8') as f:
                        current_text = f.read().strip()
                        logger.info(f"Extracted text from text file: {filename}")
                else:
                    # Use Google Vision API
                    with io.open(file_path, 'rb') as image_file:
                        content = image_file.read()

                    image = vision.Image(content=content)
                    response = vision_client.text_detection(image=image)
                    
                    if response.error.message:
                        logger.error(f"Google Vision API error for {filename}: {response.error.message}")
                        continue
                        
                    if response.text_annotations:
                        current_text = response.text_annotations[0].description.strip()
                        logger.info(f"Extracted text from image: {filename}")
                    else:
                        logger.warning(f"No text detected in {filename}")
                        continue

                if current_text:
                    # extracted text with clear file separation
                    file_text = f"=== Content from {filename} ===\n{current_text}"
                    extracted_text.append(file_text)
                    processed_count += 1
                    logger.info(f"Successfully added text from {filename}")

            except Exception as e:
                logger.error(f"Error processing file {file.filename}: {str(e)}")
                continue

        # Log processing summary
        logger.info(f"Processed {processed_count}/{total_files} files successfully")
        
        if not extracted_text:
            logger.warning("No text was extracted from any files")
            return "", [], []

        # Combine all extracted text with clear separation
        final_text = "\n\n".join(extracted_text)
        logger.info(f"Generated combined text from {len(extracted_text)} files")
        logger.info(f"Files processed: {', '.join(filenames)}")
        
        return final_text, file_paths, filenames
    
# Async support for Flask
def async_to_sync(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(func(*args, **kwargs))
        finally:
            loop.close()
    return wrapper

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))
# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            next_page = request.args.get('next')
            return redirect(next_page or url_for('dashboard'))
        flash('Invalid username or password')
    
    return render_template('login.html', form=form)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    form = RegistrationForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash('Username already exists')
        else:
            user = User(username=form.username.data)
            user.set_password(form.password.data)
            db.session.add(user)
            try:
                db.session.commit()
                flash('Registration successful! Please login.')
                return redirect(url_for('login'))
            except Exception as e:
                db.session.rollback()
                logger.error(f"Registration error: {str(e)}")
                flash('Registration failed. Please try again.')
    
    return render_template('register.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        # Get recent sessions with their analyses, ordered by creation date
        recent_sessions = (
            Session.query
            .filter_by(user_id=current_user.id)
            .order_by(Session.created_at.desc())
            .all()
        )
        
        return render_template(
            'dashboard.html',
            recent_sessions=recent_sessions,
            user=current_user
        )
        

        
        logger.info(f"Found {len(recent_sessions)} recent sessions for user {current_user.id}")
        
        # Debug log sessions
        for session in recent_sessions:
            analyses = session.analyses
            logger.debug(f"Session {session.id}:")
            logger.debug(f"  Company: {session.company_name}")
            logger.debug(f"  Created: {session.created_at}")
            logger.debug(f"  Analyses: {len(analyses)}")
            
            if analyses:
                latest = analyses[0]
                logger.debug(f"  Latest analysis type: {latest.vulnerability_type}")
                logger.debug(f"  Latest analysis severity: {latest.severity}")

        return render_template(
            'dashboard.html',
            recent_sessions=recent_sessions,
            user=current_user
        )
        
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        flash('Error loading dashboard', 'error')
        return redirect(url_for('index'))
    
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024  # 10MB max file size

@app.route('/upload', methods=['POST'])
@login_required
@async_to_sync
async def upload_file():
    try:
        logger.info("Starting file upload process")
        
        files = []
        if 'file' in request.files:
            files = [request.files['file']]
            logger.info("Single file upload detected")
        elif 'files[]' in request.files:
            files = request.files.getlist('files[]')
            logger.info(f"Multiple files upload detected: {len(files)} files")

        if not files:
            logger.error("No files uploaded")
            return jsonify({'error': 'No files uploaded'}), 400

        # Create session
        session_id = str(uuid.uuid4())
        new_session = Session(id=session_id, user_id=current_user.id)
        db.session.add(new_session)
        logger.info(f"Created new session: {session_id}")

        # Process files and extract text
        file_paths = []
        filenames = []
        extracted_texts = []

        for file in files:
            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                logger.info(f"Processing file: {filename}")

                # Create user-specific directory
                user_upload_dir = os.path.join(
                    current_app.config['UPLOAD_FOLDER'],
                    current_user.username,
                    session_id
                )
                os.makedirs(user_upload_dir, exist_ok=True)

                # Save file
                file_path = save_file(current_user.username, session_id, file)
                if file_path:
                    file_paths.append(file_path)
                    filenames.append(filename)

                    # Extract text
                    extracted_text = None
                    if file_path.lower().endswith('.txt'):
                        with open(file_path, 'r', encoding='utf-8') as f:
                            extracted_text = f.read().strip()
                    else:
                        extracted_text = extract_text_with_google_vision(file_path)

                    if extracted_text:
                        extracted_texts.append(extracted_text)
                        logger.info(f"Extracted text from {filename}: {len(extracted_text)} characters")

        if not file_paths:
            logger.error("No valid files processed")
            return jsonify({'error': 'No valid files processed'}), 400

        # Combine extracted text
        combined_text = "\n\n=== File Contents ===\n\n".join(extracted_texts)

        # Analyze text
        analysis_result = await security_analyzer.analyze(combined_text)
        logger.info("Successfully received analysis response")

        if not analysis_result:
            logger.error("Analysis failed")
            return jsonify({'error': 'Analysis failed'}), 500

        # Prepare file information
        file_info = {
            'files': [
                {
                    'name': name,
                    'path': path,
                    'full_path': os.path.join(current_app.config['UPLOAD_FOLDER'], path)
                } for name, path in zip(filenames, file_paths)
            ],
            'total_files': len(file_paths)
        }

        # Create analysis record
        analysis = Analysis(
            session_id=session_id,
            image_path=json.dumps(file_paths),
            extracted_text=combined_text,
            vulnerability_type=analysis_result.vulnerability_type,
            severity=analysis_result.severity,
            confidence=analysis_result.confidence,
            impact=analysis_result.impact,
            cwe_id=analysis_result.cwe_id,
            cvss_score=analysis_result.cvss_score,
            evidence=json.dumps(analysis_result.evidence or []),
            recommendations=json.dumps(analysis_result.recommendations or []),
            affected_components=json.dumps(analysis_result.affected_components or []),
            references=json.dumps(analysis_result.references or []),
            false_positives=json.dumps(analysis_result.false_positives or []),
            attack_vectors=json.dumps(analysis_result.attack_vectors or []),
            file_info=json.dumps(file_info)
        )

        db.session.add(analysis)

        try:
            db.session.commit()
            logger.info(f"Successfully saved analysis for session {session_id}")
        except Exception as e:
            db.session.rollback()
            logger.error(f"Database error: {str(e)}")
            return jsonify({'error': 'Failed to save analysis results'}), 500

        return jsonify({
            'success': True,
            'session_id': session_id,
            'analysis': {
                'vulnerability_type': analysis_result.vulnerability_type,
                'severity': analysis_result.severity,
                'confidence': analysis_result.confidence,
                'impact': analysis_result.impact,
                'cwe_id': analysis_result.cwe_id,
                'cvss_score': analysis_result.cvss_score,
                'evidence': analysis_result.evidence,
                'recommendations': analysis_result.recommendations,
                'affected_components': analysis_result.affected_components,
                'file_info': file_info,
                'image_paths': file_paths,
                'extracted_text': combined_text
            }
        })

    except Exception as e:
        logger.error(f"Upload error: {str(e)}")
        return jsonify({'error': str(e)}), 500

def async_to_sync(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(func(*args, **kwargs))
        finally:
            loop.close()
    return wrapper
class BatchAnalyzer:
    def __init__(self, security_analyzer):
        self.security_analyzer = security_analyzer
        self.logger = logging.getLogger(__name__)

    async def analyze_batch(self, files, user, session_id):
        """
        Analyze multiple files in a single batch.
        
        Args:
            files: List of file objects
            user: Current user object
            session_id: Session ID for the batch
        """
        analysis_results = []
        filenames = []
        combined_evidence = []
        total_cvss_score = 0
        total_confidence = 0
        all_recommendations = set()
        all_affected_components = set()
        all_vulnerabilities = set()
        highest_severity = 'Low'
        
        severity_order = {
            'Critical': 4,
            'High': 3,
            'Medium': 2,
            'Low': 1
        }

        for file in files:
            try:
                if not file or not allowed_file(file.filename):
                    continue

                filename = secure_filename(file.filename)
                filenames.append(filename)
                
                # Save and process file
                file_path = save_file(user.username, session_id, file)
                if not file_path:
                    continue

                # Extract text based on file type
                extracted_text = None
                if file_path.lower().endswith('.txt'):
                    with open(file_path, 'r', encoding='utf-8') as f:
                        extracted_text = f.read()
                else:
                    extracted_text = extract_text_with_google_vision(file_path)

                if not extracted_text:
                    self.logger.warning(f"No text could be extracted from {filename}")
                    continue

                # Analyze the content
                analysis_result = await self.security_analyzer.analyze(extracted_text)
                
                if not analysis_result:
                    self.logger.warning(f"Analysis failed for {filename}")
                    continue

                # Update metrics
                current_severity = analysis_result.severity
                if severity_order.get(current_severity, 0) > severity_order.get(highest_severity, 0):
                    highest_severity = current_severity

                total_cvss_score += analysis_result.cvss_score
                total_confidence += analysis_result.confidence
                
                if analysis_result.evidence:
                    combined_evidence.extend(analysis_result.evidence)
                
                if analysis_result.recommendations:
                    all_recommendations.update(analysis_result.recommendations)
                
                if analysis_result.affected_components:
                    all_affected_components.update(analysis_result.affected_components)
                
                if analysis_result.vulnerability_type:
                    all_vulnerabilities.add(analysis_result.vulnerability_type)

                # Store individual result
                result_data = {
                    'filename': filename,
                    'file_path': file_path,
                    'vulnerability_type': analysis_result.vulnerability_type,
                    'severity': analysis_result.severity,
                    'confidence': analysis_result.confidence,
                    'impact': analysis_result.impact,
                    'cvss_score': analysis_result.cvss_score,
                    'cwe_id': analysis_result.cwe_id,
                    'evidence': analysis_result.evidence,
                    'recommendations': analysis_result.recommendations,
                    'affected_components': analysis_result.affected_components,
                    'extracted_text': extracted_text
                }
                analysis_results.append(result_data)

            except Exception as e:
                self.logger.error(f"Error processing file {file.filename}: {str(e)}")
                continue

        # Calculate aggregated metrics
        num_files = len(analysis_results)
        if num_files == 0:
            return None

        avg_cvss = total_cvss_score / num_files
        avg_confidence = total_confidence / num_files

        return {
            'individual_results': analysis_results,
            'aggregated_results': {
                'vulnerability_type': ', '.join(all_vulnerabilities),
                'severity': highest_severity,
                'confidence': round(avg_confidence, 2),
                'impact': "Multiple vulnerabilities detected across files" if num_files > 1 
                         else analysis_results[0]['impact'],
                'cvss_score': round(avg_cvss, 2),
                'evidence': combined_evidence,
                'recommendations': list(all_recommendations),
                'affected_components': list(all_affected_components),
                'files_analyzed': filenames,
                'total_files': num_files
            }
        }
@app.route('/api/analyze-multiple', methods=['POST'])
@login_required
@async_to_sync
async def analyze_multiple_files():
    try:
        if 'files[]' not in request.files:
            return jsonify({'error': 'No files uploaded'}), 400

        files = request.files.getlist('files[]')
        if not files:
            return jsonify({'error': 'No files selected'}), 400

        # Create a new session for this batch
        session_id = str(uuid.uuid4())
        new_session = Session(id=session_id, user_id=current_user.id)
        db.session.add(new_session)

        # Process all files and store results
        all_results = []
        critical_count = 0
        total_risk_score = 0
        
        for file in files:
            if not allowed_file(file.filename):
                continue

            # Save file
            file_path = save_file(current_user.username, session_id, file)
            if not file_path:
                continue

            try:
                # Extract text from file
                if file_path.lower().endswith('.txt'):
                    with open(file_path, 'r', encoding='utf-8') as f:
                        extracted_text = f.read()
                else:
                    extracted_text = extract_text_with_google_vision(file_path)

                if not extracted_text:
                    continue

                # Analyze the text
                analysis_result = await security_analyzer.analyze(extracted_text)
                
                if not analysis_result:
                    analysis_result = security_analyzer._get_default_result()
                    ml_result = None
                else:
                    ml_result = True

                # Create analysis record
                new_analysis = Analysis(
                    session_id=session_id,
                    image_path=file_path,
                    extracted_text=extracted_text,
                    vulnerability_type=analysis_result.vulnerability_type,
                    severity=analysis_result.severity,
                    confidence=analysis_result.confidence,
                    impact=analysis_result.impact,
                    cwe_id=analysis_result.cwe_id,
                    cvss_score=analysis_result.cvss_score,
                    evidence=json.dumps(analysis_result.evidence or []),
                    recommendations=json.dumps(analysis_result.recommendations or []),
                    affected_components=json.dumps(analysis_result.affected_components or []),
                    references=json.dumps(analysis_result.references or []),
                    false_positives=json.dumps(analysis_result.false_positives or []),
                    attack_vectors=json.dumps(analysis_result.attack_vectors or []),
                    analysis_sources=json.dumps({
                        'pattern': True,
                        'ml': bool(ml_result),
                        'lora': bool(ml_result)
                    })
                )
                db.session.add(new_analysis)

                #  aggregate metrics
                if analysis_result.severity == 'Critical':
                    critical_count += 1
                total_risk_score += analysis_result.cvss_score

                # Add to results list
                all_results.append({
                    'vulnerability_type': analysis_result.vulnerability_type,
                    'severity': analysis_result.severity,
                    'confidence': analysis_result.confidence,
                    'impact': analysis_result.impact,
                    'cwe_id': analysis_result.cwe_id,
                    'cvss_score': analysis_result.cvss_score,
                    'recommendations': analysis_result.recommendations
                })

            except Exception as e:
                logger.error(f"Analysis error for file {file.filename}: {str(e)}")
                continue

        # Commit all database changes
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            logger.error(f"Database error: {str(e)}")
            return jsonify({'error': 'Database error'}), 500

        # Calculate aggregate metrics
        num_files = len(all_results)
        if num_files > 0:
            aggregate_score = total_risk_score / num_files
        else:
            aggregate_score = 0

        return jsonify({
            'success': True,
            'session_id': session_id,
            'results': all_results,
            'aggregateScore': aggregate_score,
            'criticalCount': critical_count
        })

    except Exception as e:
        logger.error(f"Multiple file analysis error: {str(e)}")
        return jsonify({'error': str(e)}), 500
    
@app.route('/uploads/<path:filename>')
@login_required
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)    

logger = logging.getLogger(__name__)

def calculate_risk_metrics(analysis) -> Dict:
    """Calculate comprehensive risk metrics for executive reporting."""
    try:
        # Base risk calculation
        base_risk_score = analysis.confidence * 10
        
        # Calculate risk trend based on severity and confidence
        severity_weights = {
            'Critical': 1.5,
            'High': 1.2,
            'Medium': 1.0,
            'Low': 0.5
        }
        weight = severity_weights.get(analysis.severity, 1.0)
        
        # Calculate historical trend (simulated)
        historical_scores = [
            base_risk_score * 0.9,  # 3 months ago
            base_risk_score * 0.95,  # 2 months ago
            base_risk_score         # Current
        ]
        
        # Determine trend direction
        trend_direction = 'Increasing' if historical_scores[-1] > historical_scores[-2] else 'Decreasing'
        trend_percentage = abs((historical_scores[-1] - historical_scores[-2]) / historical_scores[-2] * 100)
        
        # Risk distribution calculation
        risk_counts = {
            'critical': 3 if analysis.severity == 'Critical' else 1,
            'high': 4 if analysis.severity in ['Critical', 'High'] else 2,
            'medium': 5 if analysis.severity != 'Low' else 3,
            'low': 3
        }
        
        return {
            'base_score': base_risk_score,
            'adjusted_score': base_risk_score * weight,
            'risk_level': analysis.severity,
            'confidence': analysis.confidence,
            'trend': trend_direction,
            'trend_percentage': f"{trend_percentage:.1f}%",
            'historical_scores': historical_scores,
            'risk_counts': risk_counts,
            'weight': weight,
            'risk_categories': {
                'infrastructure': base_risk_score * 0.8,
                'application': base_risk_score * 0.9,
                'data': base_risk_score * 0.85,
                'network': base_risk_score * 0.75
            }
        }
    except Exception as e:
        logger.error(f"Error calculating risk metrics: {e}")
        return {
            'base_score': 5.0,
            'adjusted_score': 5.0,
            'risk_level': 'Medium',
            'confidence': 0.5,
            'trend': 'Stable',
            'trend_percentage': '0%',
            'historical_scores': [5.0, 5.0, 5.0],
            'risk_counts': {'critical': 0, 'high': 1, 'medium': 2, 'low': 1},
            'weight': 1.0,
            'risk_categories': {
                'infrastructure': 4.0,
                'application': 4.5,
                'data': 4.25,
                'network': 3.75
            }
        }

def calculate_business_impact(analysis) -> Dict:
    """Calculate detailed business impact assessment."""
    try:
        # Define impact levels based on severity
        impact_levels = {
            'Critical': {
                'financial': {
                    'direct_loss': 750000,
                    'indirect_cost': 250000,
                    'total': 1000000,
                    'display': '$1,000,000+'
                },
                'operational': {
                    'severity': 'Severe',
                    'recovery_time': '1-2 Weeks',
                    'business_units': ['IT', 'Security', 'Operations', 'Business'],
                    'service_impact': 'Critical Service Disruption'
                },
                'compliance': {
                    'status': 'Major Violations',
                    'frameworks': ['NCA', 'ISO27001', 'PCI DSS'],
                    'penalty_risk': 'High',
                    'remediation_urgency': 'Immediate'
                },
                'reputational': {
                    'severity': 'Severe',
                    'stakeholders': ['Customers', 'Partners', 'Regulators', 'Public'],
                    'media_risk': 'High',
                    'recovery_time': '6-12 months'
                }
            },
            # Add other severity levels...
        }
        
        impact_data = impact_levels.get(analysis.severity, impact_levels['Critical'])
        
        # Calculate potential loss prevention
        loss_prevention = {
            'immediate': impact_data['financial']['total'] * 0.7,
            'short_term': impact_data['financial']['total'] * 0.2,
            'long_term': impact_data['financial']['total'] * 0.1
        }
        
        return {
            'financial': impact_data['financial'],
            'operational': impact_data['operational'],
            'compliance': impact_data['compliance'],
            'reputational': impact_data['reputational'],
            'loss_prevention': loss_prevention,
            'total_impact': impact_data['financial']['total'],
            'mitigation_benefits': {
                'cost_avoidance': impact_data['financial']['total'],
                'operational_savings': impact_data['financial']['total'] * 0.25,
                'compliance_benefits': impact_data['financial']['total'] * 0.15
            }
        }
    except Exception as e:
        logger.error(f"Error calculating business impact: {e}")
        return {
            'financial': {'total': 100000, 'display': '$100,000+'},
            'operational': {'severity': 'Moderate'},
            'compliance': {'status': 'Minor Violations'},
            'reputational': {'severity': 'Low'}
        }

def calculate_compliance_metrics(analysis) -> Dict:
    """Calculate comprehensive compliance metrics."""
    try:
        is_critical = analysis.severity == 'Critical'
        is_high = analysis.severity == 'High'
        
        frameworks = {
            'nca': {
                'name': 'NCA Framework',
                'status': 'Non-Compliant' if is_critical else 'Compliant',
                'score': 60 if is_critical else 85,
                'gap': 40 if is_critical else 15,
                'priority': 'Immediate Action Required' if is_critical else 'Monitoring Required',
                'controls': {
                    'implemented': 75,
                    'partial': 15,
                    'missing': 10
                }
            },
            'iso27001': {
                'name': 'ISO 27001',
                'status': 'Partially Compliant',
                'score': 75,
                'gap': 25,
                'priority': 'Action Required' if is_critical or is_high else 'Review Required',
                'controls': {
                    'implemented': 80,
                    'partial': 15,
                    'missing': 5
                }
            },
            'pci_dss': {
                'name': 'PCI DSS',
                'status': 'At Risk' if is_critical else 'Partially Compliant',
                'score': 65 if is_critical else 80,
                'gap': 35 if is_critical else 20,
                'priority': 'Immediate Review Required' if is_critical else 'Scheduled Review',
                'controls': {
                    'implemented': 70,
                    'partial': 20,
                    'missing': 10
                }
            }
        }
        
        return frameworks
    except Exception as e:
        logger.error(f"Error calculating compliance metrics: {e}")
        return {}

class ReportGenerationAssistant:
    def __init__(self, api_key: str, assistant_id: str = "asst_2ZsSx8Cvn6k7HX6zZXemEwqK"):  # Updated default ID
        self.client = OpenAI(api_key=api_key)
        self.assistant_id = assistant_id
        self.logger = logging.getLogger(__name__)
        self.max_retries = 3
        self.retry_delay = 2
        self.timeout = 120

    async def _create_thread(self):
        """Create a new thread with error handling."""
        try:
            thread = self.client.beta.threads.create()
            self.logger.info(f"Created thread: {thread.id}")
            return thread
        except Exception as e:
            self.logger.error(f"Failed to create thread: {str(e)}")
            return None

    async def _add_message(self, thread_id: str, content: str) -> bool:
        """Add message to thread."""
        try:
            message = self.client.beta.threads.messages.create(
                thread_id=thread_id,
                role="user",
                content=content
            )
            self.logger.info(f"Added message to thread {thread_id}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to add message: {str(e)}")
            return False

    async def _run_assistant(self, thread_id: str):
        """Start assistant run."""
        try:
            run = self.client.beta.threads.runs.create(
                thread_id=thread_id,
                assistant_id=self.assistant_id
            )
            self.logger.info(f"Started run {run.id} for thread {thread_id}")
            return run
        except Exception as e:
            self.logger.error(f"Failed to start run: {str(e)}")
            return None

    async def analyze_for_report(self, analysis_data: Dict) -> Dict:
        """
        Analyze vulnerability data and generate comprehensive report metrics.
        """
        try:
            # Create analysis prompt
            prompt = self._create_report_prompt(analysis_data)
            
            # Create thread and add message
            thread = await self._create_thread()
            if not thread:
                return self._get_default_metrics()
                
            message_added = await self._add_message(thread.id, prompt)
            if not message_added:
                return self._get_default_metrics()

            # Run analysis
            run = await self._run_assistant(thread.id)
            if not run:
                return self._get_default_metrics()

            # Wait for completion
            result = await self._wait_for_completion(thread.id, run.id)
            if result:
                metrics = self._parse_report_metrics(result)
                # Ensure risk_counts is present
                if 'risk_metrics' in metrics:
                    metrics['risk_metrics']['risk_counts'] = {
                        'critical': metrics['risk_metrics']['risk_distribution'].get('critical', 0),
                        'high': metrics['risk_metrics']['risk_distribution'].get('high', 0),
                        'medium': metrics['risk_metrics']['risk_distribution'].get('medium', 0),
                        'low': metrics['risk_metrics']['risk_distribution'].get('low', 0)
                    }
                return metrics
                
            return self._get_default_metrics()

        except Exception as e:
            self.logger.error(f"Report analysis error: {str(e)}")
            return self._get_default_metrics()

    def _create_report_prompt(self, analysis_data: Dict) -> str:
            """Create detailed prompt for report metric generation with enhanced MITRE ATT&CK analysis."""
            return f"""Analyze this security vulnerability data and generate comprehensive report metrics with detailed MITRE ATT&CK mapping:

        Vulnerability Context:
        - Type: {analysis_data.get('vulnerability_type')}
        - Severity: {analysis_data.get('severity')}
        - CVSS Score: {analysis_data.get('cvss_score')}
        - CWE ID: {analysis_data.get('cwe_id')}
        - Impact: {analysis_data.get('impact')}
        - Evidence: {json.dumps(analysis_data.get('evidence', []))}
        - Extracted Text: {analysis_data.get('extracted_text')}

        Generate detailed report metrics including risk assessment, business impact, compliance impact, 
        resource requirements, cost analysis, timeline estimates, personnel requirements, and an enhanced MITRE ATT&CK analysis.

        Focus on MITRE ATT&CK Analysis:
        1. Tactical Analysis:
        - Map vulnerability to specific MITRE ATT&CK tactics
        - Identify all applicable techniques and sub-techniques
        - Evaluate likelihood and impact for each tactic
        - Assess detection confidence based on provided evidence
        - Link to relevant threat actor behaviors

        2. Technical Details:
        - Provide specific technique IDs and descriptions
        - Include detailed sub-technique breakdowns
        - Map to real-world attack scenarios
        - Document common procedure examples
        - List required data sources for detection

        3. Kill Chain Mapping:
        - Detail each attack phase
        - Identify indicators and detection opportunities
        - Provide phase duration estimates
        - Map techniques to kill chain phases
        - Include adversary behaviors

        4. Detection & Mitigation:
        - Specify monitoring requirements
        - Detail detection strategies
        - Provide false positive rates
        - Include mitigation recommendations
        - List implementation prerequisites

        Provide your response in this exact JSON format:
        {{
            "risk_metrics": {{
                "base_score": float,
                "adjusted_score": float,
                "risk_level": string,
                "confidence": float,
                "trend": string,
                "trend_percentage": string,
                "risk_distribution": {{
                    "critical": int,
                    "high": int,
                    "medium": int,
                    "low": int
                }},
                "risk_categories": {{
                    "infrastructure": float,
                    "application": float,
                    "data": float,
                    "network": float
                }}
            }},
            "business_impact": {{
                "financial": {{
                    "direct_loss": int,
                    "indirect_cost": int,
                    "total": int,
                    "display": string
                }},
                "operational": {{
                    "severity": string,
                    "recovery_time": string,
                    "business_units": [string],
                    "service_impact": string
                }},
                "compliance": {{
                    "status": string,
                    "frameworks": [string],
                    "penalty_risk": string,
                    "remediation_urgency": string
                }},
                "reputational": {{
                    "severity": string,
                    "stakeholders": [string],
                    "media_risk": string,
                    "recovery_time": string
                }}
            }},
            "compliance": {{
                "frameworks": {{
                    "nca": {{
                        "name": string,
                        "status": string,
                        "score": int,
                        "gap": int,
                        "priority": string,
                        "controls": {{
                            "implemented": int,
                            "partial": int,
                            "missing": int
                        }},
                        "details": {{
                            "last_assessment": string,
                            "next_review": string,
                            "control_categories": {{
                                "access_control": int,
                                "data_protection": int,
                                "incident_response": int,
                                "system_security": int
                            }}
                        }}
                    }},
                    "iso27001": {{
                        "name": string,
                        "status": string,
                        "score": int,
                        "gap": int,
                        "priority": string,
                        "controls": {{
                            "implemented": int,
                            "partial": int,
                            "missing": int
                        }},
                        "details": {{
                            "last_assessment": string,
                            "next_review": string,
                            "control_categories": {{
                                "information_security": int,
                                "asset_management": int,
                                "access_control": int,
                                "cryptography": int
                            }}
                        }}
                    }}
                }},
                "status": string,
                "priority": string,
                "overall_score": int,
                "overall_gap": int,
                "summary": {{
                    "total_controls": int,
                    "implemented_controls": int,
                    "partial_controls": int,
                    "missing_controls": int
                }}
            }},
            "resources": {{
                "immediate": {{
                    "timeline": string,
                    "cost": string,
                    "staff": int,
                    "training_cost": string,
                    "operational_savings": string,
                    "compliance_savings": string,
                    "priority": string,
                    "implementation_complexity": string,
                    "business_disruption": string,
                    "actions": [{{
                        "description": string,
                        "resources": string,
                        "impact": string,
                        "timeline": string,
                        "dependencies": [string]
                    }}],
                    "metrics": {{
                        "roi": float,
                        "payback_period": string,
                        "risk_reduction": string
                    }}
                }},
                "shortterm": {{
                    "timeline": string,
                    "cost": string,
                    "staff": int,
                    "training_cost": string,
                    "operational_savings": string,
                    "compliance_savings": string,
                    "priority": string,
                    "implementation_complexity": string,
                    "business_disruption": string,
                    "actions": [{{
                        "description": string,
                        "resources": string,
                        "impact": string,
                        "timeline": string,
                        "dependencies": [string]
                    }}],
                    "metrics": {{
                        "roi": float,
                        "payback_period": string,
                        "risk_reduction": string
                    }}
                }},
                "longterm": {{
                    "timeline": string,
                    "cost": string,
                    "staff": int,
                    "training_cost": string,
                    "operational_savings": string,
                    "compliance_savings": string,
                    "priority": string,
                    "implementation_complexity": string,
                    "business_disruption": string,
                    "actions": [{{
                        "description": string,
                        "resources": string,
                        "impact": string,
                        "timeline": string,
                        "dependencies": [string]
                    }}],
                    "metrics": {{
                        "roi": float,
                        "payback_period": string,
                        "risk_reduction": string
                    }}
                }}
            }},
            "mitre_attack": {{
                "tactics": [
                    {{
                        "tactic_id": string (format: "TAxxxx"),
                        "tactic_name": string,
                        "description": string,
                        "techniques": [
                            {{
                                "technique_id": string (format: "Txxxx"),
                                "technique_name": string,
                                "description": string,
                                "sub_techniques": [
                                    {{
                                        "sub_technique_id": string (format: "Txxxx.xxx"),
                                        "name": string,
                                        "description": string,
                                        "detection": string,
                                        "mitigation": string,
                                        "implementation": {{
                                            "complexity": string,
                                            "prerequisites": [string],
                                            "effectiveness": string,
                                            "resources_required": [string]
                                        }}
                                    }}
                                ],
                                "detection": {{
                                    "method": string,
                                    "data_sources": [string],
                                    "effectiveness": string,
                                    "false_positive_rate": string,
                                    "implementation_effort": string
                                }},
                                "mitigation": {{
                                    "strategy": string,
                                    "controls": [string],
                                    "effectiveness": string,
                                    "implementation_time": string,
                                    "cost_estimate": string
                                }},
                                "procedure_examples": [{{
                                    "description": string,
                                    "commands": [string],
                                    "detection_opportunities": [string]
                                }}],
                                "data_sources": [string],
                                "platforms": [string]
                            }}
                        ],
                        "likelihood": string,
                        "impact": string,
                        "detection_confidence": float
                    }}
                ],
                "attack_patterns": [
                    {{
                        "pattern_id": string,
                        "name": string,
                        "description": string,
                        "phases": [string],
                        "platforms": [string],
                        "severity": string,
                        "likelihood": string,
                        "prerequisites": [string],
                        "mitigations": [string],
                        "real_world_incidents": [{{
                            "description": string,
                            "impact": string,
                            "lessons_learned": string
                        }}]
                    }}
                ],
                "kill_chain_phases": [
                    {{
                        "phase_name": string,
                        "description": string,
                        "techniques_used": [string],
                        "duration": string,
                        "indicators": [string],
                        "detection_opportunities": [string],
                        "adversary_behaviors": [string],
                        "defense_recommendations": [string]
                    }}
                ],
                "summary": string,
                "recommendations": [
                    {{
                        "priority": string,
                        "description": string,
                        "implementation": string,
                        "effectiveness": string,
                        "cost_estimate": string,
                        "timeframe": string,
                        "dependencies": [string],
                        "success_metrics": [string]
                    }}
                ],
                "data_sources": [string],
                "detection_methods": [
                    {{
                        "method": string,
                        "effectiveness": string,
                        "implementation": string,
                        "data_requirements": [string],
                        "false_positive_rate": string,
                        "tuning_requirements": string,
                        "maintenance_needs": string
                    }}
                ]
            }},
            "assessment_details": {{
                "methodology": string,
                "confidence_level": string,
                "data_sources": [string],
                "limitations": [string]
            }},
            "metrics_timestamp": string (ISO format)
        }}

        Analysis Guidelines:
        1. Base calculations on severity level, CVSS score, CWE ID, and impact assessment
        2. Ensure all costs use SAR currency format
        3. Provide realistic timelines and resource estimates
        4. Create comprehensive MITRE ATT&CK mapping with real-world context
        5. Include detailed attack patterns and kill chain analysis
        6. Suggest specific detection and mitigation strategies
        7. Consider both technical and business impacts
        8. Evaluate compliance implications for NCA and ISO27001
        9. Assess resource requirements across immediate, short-term, and long-term phases
        10. Include real-world procedure examples and incident references

        For MITRE ATT&CK Analysis:
        - Map each vulnerability to specific tactics, techniques, and procedures
        - Provide detailed detection and mitigation strategies with implementation guidance
        - Include real-world procedure examples and commands
        - Map the full attack chain from initial access to impact
        - Evaluate likelihood and impact for each identified tactic
        - Provide specific monitoring methods with data source requirements
        - Include both prevention and response measures
        - Evaluate detection confidence with false positive assessments
        - Link to relevant real-world incidents and lessons learned
        - Consider environment-specific constraints and requirements"""
        
    def _parse_mitre_attack_response(self, response_text: str) -> Dict:
        """Parse and validate the MITRE ATT&CK analysis response."""
        try:
            # Extract JSON from response
            json_start = response_text.find('{')
            json_end = response_text.rfind('}') + 1
            
            if json_start >= 0 and json_end > json_start:
                json_str = response_text[json_start:json_end]
                data = json.loads(json_str)
                
                # Extract MITRE ATT&CK section
                mitre_data = data.get('mitre_attack', {})
                
                # Validate and enhance the analysis
                return self._enhance_mitre_analysis(mitre_data)
            
            return self._get_default_mitre_analysis()
            
        except Exception as e:
            self.logger.error(f"Error parsing MITRE ATT&CK analysis: {str(e)}")
            return self._get_default_mitre_analysis()

    def _enhance_mitre_analysis(self, mitre_data: Dict) -> Dict:
        """Enhance MITRE ATT&CK analysis with additional context and validation."""
        try:
            # Validate and ensure all required sections exist
            tactics = mitre_data.get('tactics', [])
            attack_patterns = mitre_data.get('attack_patterns', [])
            kill_chain_phases = mitre_data.get('kill_chain_phases', [])
            
            # Enhance tactics with additional context
            for tactic in tactics:
                # Ensure proper MITRE ATT&CK IDs
                if not tactic.get('tactic_id', '').startswith('TA'):
                    tactic['tactic_id'] = f"TA{random.randint(1000, 9999)}"
                
                # Enhance techniques
                for technique in tactic.get('techniques', []):
                    if not technique.get('technique_id', '').startswith('T'):
                        technique['technique_id'] = f"T{random.randint(1000, 9999)}"
                    
                    # Add implementation details
                    technique['implementation_details'] = {
                        'complexity': 'High' if tactic.get('detection_confidence', 0) < 0.5 else 'Medium',
                        'required_resources': ['Security Monitoring', 'Log Analysis', 'WAF'],
                        'estimated_timeline': '2-4 weeks'
                    }
            
            # Enhance attack patterns with real-world context
            for pattern in attack_patterns:
                pattern['real_world_examples'] = [
                    {
                        'incident_type': 'Known Exploitation',
                        'description': f"Previous exploitation of {pattern['name']}",
                        'impact': 'Critical data exposure and system compromise',
                        'mitigations_applied': pattern.get('mitigations', [])
                    }
                ]
            
            # Add detailed detection metrics
            detection_methods = mitre_data.get('detection_methods', [])
            for method in detection_methods:
                method['effectiveness_metrics'] = {
                    'detection_rate': '85%',
                    'false_positive_rate': method.get('false_positive_rate', 'Medium'),
                    'implementation_effort': 'Medium',
                    'maintenance_requirements': 'Regular tuning and updates'
                }
            
            return {
                'tactics': tactics,
                'attack_patterns': attack_patterns,
                'kill_chain_phases': kill_chain_phases,
                'detection_methods': detection_methods,
                'recommendations': mitre_data.get('recommendations', []),
                'summary': mitre_data.get('summary', 'Comprehensive MITRE ATT&CK analysis of identified vulnerabilities'),
                'data_sources': mitre_data.get('data_sources', [])
            }
            
        except Exception as e:
            self.logger.error(f"Error enhancing MITRE analysis: {str(e)}")
            return self._get_default_mitre_analysis()

    def _get_default_mitre_analysis(self) -> Dict:
        """Return default MITRE ATT&CK analysis structure."""
        return {
            'tactics': [{
                'tactic_id': 'TA0001',
                'tactic_name': 'Initial Access',
                'description': 'Standard initial access vector analysis',
                'techniques': [{
                    'technique_id': 'T1190',
                    'technique_name': 'Exploit Public-Facing Application',
                    'description': 'Standard exploitation technique',
                    'detection': 'Monitor application logs',
                    'mitigation': 'Regular patching and updates'
                }],
                'likelihood': 'Medium',
                'impact': 'High',
                'detection_confidence': 0.7
            }],
            'attack_patterns': [{
                'pattern_id': 'CAPEC-1',
                'name': 'Standard Attack Pattern',
                'description': 'Common attack methodology',
                'phases': ['Reconnaissance', 'Exploitation'],
                'platforms': ['Web Applications'],
                'severity': 'High',
                'likelihood': 'Medium'
            }],
            'kill_chain_phases': [{
                'phase_name': 'Initial Access',
                'description': 'Standard initial access phase',
                'techniques_used': ['Web Application Exploitation'],
                'duration': '1-2 weeks',
                'indicators': ['Suspicious HTTP requests']
            }],
            'summary': 'Default MITRE ATT&CK analysis for security vulnerabilities',
            'recommendations': [{
                'priority': 'High',
                'description': 'Implement security controls',
                'implementation': 'Standard security measures',
                'effectiveness': 'Medium',
                'cost_estimate': 'SAR 50,000',
                'timeframe': '30 days'
            }]
        }
    async def _wait_for_completion(self, thread_id: str, run_id: str) -> Optional[Dict]:
        """Wait for analysis completion with timeout."""
        start_time = time.time()
        check_interval = 1
        
        while True:
            try:
                if time.time() - start_time > self.timeout:
                    self.logger.error(f"Run {run_id} timed out after {self.timeout} seconds")
                    return None

                run_status = self.client.beta.threads.runs.retrieve(
                    thread_id=thread_id,
                    run_id=run_id
                )
                
                if run_status.status == 'completed':
                    messages = self.client.beta.threads.messages.list(
                        thread_id=thread_id,
                        order="desc",
                        limit=1
                    )
                    
                    if not messages.data:
                        return None
                        
                    return messages.data[0].content[0].text.value

                elif run_status.status in ['failed', 'cancelled', 'expired']:
                    return None

                await asyncio.sleep(check_interval)
                
            except Exception as e:
                self.logger.error(f"Error checking run status: {str(e)}")
                return None

    def _parse_report_metrics(self, response: str) -> Dict:
        """Parse AI response into report metrics format."""
        try:
            # Extract JSON from response
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            
            if json_start >= 0 and json_end > json_start:
                json_str = response[json_start:json_end]
                try:
                    metrics = json.loads(json_str)
                    # Add risk_counts if missing
                    if 'risk_metrics' in metrics:
                        metrics['risk_metrics']['risk_counts'] = {
                            'critical': metrics['risk_metrics']['risk_distribution'].get('critical', 0),
                            'high': metrics['risk_metrics']['risk_distribution'].get('high', 0),
                            'medium': metrics['risk_metrics']['risk_distribution'].get('medium', 0),
                            'low': metrics['risk_metrics']['risk_distribution'].get('low', 0)
                        }
                    return metrics
                except json.JSONDecodeError:
                    self.logger.error("Failed to parse JSON response")
                    return self._get_default_metrics()
            else:
                self.logger.warning("No JSON found in response")
                return self._get_default_metrics()

        except Exception as e:
            self.logger.error(f"Response parsing error: {str(e)}")
            return self._get_default_metrics()

    def _get_default_metrics(self) -> Dict:
        """
        Return comprehensive default report metrics with proper structure.
        
        Returns:
            Dict: Complete metrics structure including:
                - Risk metrics
                - Business impact
                - Compliance (NCA, ISO27001, PCI DSS)
                - Resources
                - MITRE ATT&CK analysis
                - Assessment details
        """
        current_time = datetime.now(timezone.utc).isoformat()
        
        return {
            "risk_metrics": {
                "base_score": 5.0,
                "adjusted_score": 5.0,
                "risk_level": "Medium",
                "confidence": 0.5,
                "trend": "Stable",
                "trend_percentage": "0%",
                "risk_distribution": {
                    "critical": 0,
                    "high": 1,
                    "medium": 2,
                    "low": 1
                },
                "risk_categories": {
                    "infrastructure": 4.0,
                    "application": 4.5,
                    "data": 4.25,
                    "network": 3.75,
                    "cloud_security": 4.0,
                    "endpoint_security": 3.9,
                    "iot_security": 3.5
                },
                "risk_counts": {
                    "critical": 0,
                    "high": 1,
                    "medium": 2,
                    "low": 1
                },
                "risk_trends": {
                    "monthly_change": "+0.5%",
                    "quarterly_change": "-1.2%",
                    "yearly_change": "-3.5%",
                    "trend_analysis": "Improving with recent slight increase"
                    }
                },
                        "business_impact": {
                "financial": {
                    "direct_loss": 100000,
                    "indirect_cost": 50000,
                    "total": 150000,
                    "display": "SAR 150,000+",
                    "breakdown": {
                        "immediate_costs": "SAR 50,000",
                        "operational_costs": "SAR 30,000",
                        "recovery_costs": "SAR 40,000",
                        "long_term_costs": "SAR 30,000"
                    },
                    "roi_analysis": {
                        "investment_required": "SAR 200,000",
                        "expected_savings": "SAR 500,000",
                        "payback_period": "12 months",
                        "roi_percentage": "150%"
                    }
                },
                "operational": {
                    "severity": "Moderate",
                    "recovery_time": "1-2 weeks",
                    "business_units": ["IT", "Security", "Operations", "Finance", "Legal"],
                    "service_impact": "Moderate Service Disruption",
                    "operational_metrics": {
                        "system_downtime": "4 hours",
                        "service_degradation": "24 hours",
                        "staff_productivity": "75%",
                        "customer_impact": "Minimal"
                    }
                },
                "compliance": {
                    "status": "Partial Compliance",
                    "frameworks": [
                        "NCA Essential Cybersecurity Controls",
                        "ISO27001",
                        "PCI DSS",
                        "SAMA Cybersecurity Framework",
                        "Saudi Data & AI Authority (SDAIA) Regulations"
                    ],
                    "penalty_risk": "Medium",
                    "remediation_urgency": "Standard",
                    "regulatory_impact": {
                        "local_regulations": "High",
                        "international_regulations": "Medium",
                        "industry_specific": "Medium"
                    }
                },
                "reputational": {
                    "severity": "Low",
                    "stakeholders": [
                        "Internal",
                        "Partners",
                        "Customers",
                        "Regulators",
                        "Media"
                    ],
                    "media_risk": "Low",
                    "recovery_time": "1 month",
                    "impact_areas": {
                        "brand_value": "Minimal Impact",
                        "customer_trust": "Moderate Impact",
                        "market_position": "Low Impact",
                        "partner_relations": "Minimal Impact"
                    }
                }
            },
            "compliance": {
                "frameworks": {
                    "nca": {
                        "name": "NCA Essential Cybersecurity Controls",
                        "status": "Partial",
                        "score": 75,
                        "gap": 25,
                        "priority": "Medium",
                        "controls": {
                            "implemented": 75,
                            "partial": 15,
                            "missing": 10
                        },
                        "details": {
                            "last_assessment": "2024-01-01",
                            "next_review": "2024-06-30",
                            "control_categories": {
                                "access_control": 80,
                                "data_protection": 75,
                                "incident_response": 70,
                                "system_security": 75,
                                "cloud_security": 72,
                                "application_security": 78,
                                "network_security": 76,
                                "cryptography": 82
                            },
                            "compliance_level": {
                                "ecs_1": "Compliant",
                                "ecs_2": "Partially Compliant",
                                "ecs_3": "Non-Compliant",
                                "ecs_4": "Compliant"
                            }
                        }
                    },
                    "sama": {
                        "name": "SAMA Cybersecurity Framework",
                        "status": "Partial",
                        "score": 78,
                        "gap": 22,
                        "priority": "High",
                        "controls": {
                            "implemented": 78,
                            "partial": 12,
                            "missing": 10
                        },
                        "details": {
                            "last_assessment": "2024-01-01",
                            "next_review": "2024-06-30",
                            "control_categories": {
                                "cybersecurity_governance": 80,
                                "cybersecurity_risk": 75,
                                "cybersecurity_operations": 78,
                                "third_party": 76
                            }
                        }
                    },
                    "iso27001": {
                        "name": "ISO 27001",
                        "status": "Partial",
                        "score": 70,
                        "gap": 30,
                        "priority": "Medium",
                        "controls": {
                            "implemented": 70,
                            "partial": 20,
                            "missing": 10
                        },
                        "details": {
                            "last_assessment": "2024-01-01",
                            "next_review": "2024-06-30",
                            "control_categories": {
                                "information_security": 75,
                                "asset_management": 70,
                                "access_control": 65,
                                "cryptography": 70,
                                "physical_security": 72,
                                "operations_security": 68,
                                "communications_security": 71
                            }
                        }
                    }
                },
                "status": "Requires Review",
                "priority": "Medium",
                "overall_score": 75,
                "overall_gap": 25,
                "summary": {
                    "total_controls": 324,
                    "implemented_controls": 243,
                    "partial_controls": 49,
                    "missing_controls": 32,
                    "critical_gaps": 8,
                    "high_priority_gaps": 12
                }
            },
                    "resources": {
                "immediate": {
                    "timeline": "30 days",
                    "cost": "SAR 50,000",
                    "staff": 2,
                    "training_cost": "SAR 10,000",
                    "operational_savings": "SAR 100,000",
                    "compliance_savings": "SAR 200,000",
                    "priority": "Medium",
                    "implementation_complexity": "Moderate",
                    "business_disruption": "Low",
                    "actions": [
                        {
                            "description": "Implement security controls",
                            "resources": "2 FTE",
                            "impact": "Medium Risk Mitigation",
                            "timeline": "2 weeks",
                            "dependencies": ["Security Team Availability"],
                            "milestones": [
                                {
                                    "name": "Initial Assessment",
                                    "duration": "3 days",
                                    "resources_needed": "1 FTE"
                                },
                                {
                                    "name": "Implementation",
                                    "duration": "1 week",
                                    "resources_needed": "2 FTE"
                                },
                                {
                                    "name": "Testing",
                                    "duration": "4 days",
                                    "resources_needed": "1 FTE"
                                }
                            ]
                        }
                    ],
                    "metrics": {
                        "roi": 2.5,
                        "payback_period": "6 months",
                        "risk_reduction": "40%",
                        "compliance_improvement": "25%"
                    }
                },
                "shortterm": {
                    "timeline": "90 days",
                    "cost": "SAR 100,000",
                    "staff": 3,
                    "training_cost": "SAR 25,000",
                    "operational_savings": "SAR 150,000",
                    "compliance_savings": "SAR 300,000",
                    "priority": "Medium",
                    "implementation_complexity": "High",
                    "business_disruption": "Medium",
                    "actions": [
                        {
                            "description": "Enhance monitoring capabilities",
                            "resources": "3 FTE",
                            "impact": "Improved Detection and Response",
                            "timeline": "3 months",
                            "dependencies": ["Tool Implementation", "Team Training"],
                            "milestones": [
                                {
                                    "name": "Tool Selection",
                                    "duration": "2 weeks",
                                    "resources_needed": "1 FTE"
                                },
                                {
                                    "name": "Infrastructure Setup",
                                    "duration": "3 weeks",
                                    "resources_needed": "2 FTE"
                                },
                                {
                                    "name": "Team Training",
                                    "duration": "2 weeks",
                                    "resources_needed": "3 FTE"
                                },
                                {
                                    "name": "Integration and Testing",
                                    "duration": "4 weeks",
                                    "resources_needed": "2 FTE"
                                }
                            ]
                        }
                    ],
                    "metrics": {
                        "roi": 2.0,
                        "payback_period": "12 months",
                        "risk_reduction": "60%",
                        "compliance_improvement": "40%"
                    }
                },
                "longterm": {
                    "timeline": "180 days",
                    "cost": "SAR 200,000",
                    "staff": 4,
                    "training_cost": "SAR 50,000",
                    "operational_savings": "SAR 400,000",
                    "compliance_savings": "SAR 500,000",
                    "priority": "Low",
                    "implementation_complexity": "Very High",
                    "business_disruption": "High",
                    "actions": [
                        {
                            "description": "Implement Zero Trust Architecture",
                            "resources": "4 FTE",
                            "impact": "Comprehensive Security Enhancement",
                            "timeline": "6 months",
                            "dependencies": ["Architecture Review", "Infrastructure Updates"],
                            "milestones": [
                                {
                                    "name": "Architecture Assessment",
                                    "duration": "1 month",
                                    "resources_needed": "2 FTE"
                                },
                                {
                                    "name": "Design and Planning",
                                    "duration": "1 month",
                                    "resources_needed": "3 FTE"
                                },
                                {
                                    "name": "Infrastructure Updates",
                                    "duration": "2 months",
                                    "resources_needed": "4 FTE"
                                },
                                {
                                    "name": "Implementation",
                                    "duration": "1 month",
                                    "resources_needed": "4 FTE"
                                },
                                {
                                    "name": "Testing and Validation",
                                    "duration": "1 month",
                                    "resources_needed": "3 FTE"
                                }
                            ]
                        }
                    ],
                    "metrics": {
                        "roi": 3.0,
                        "payback_period": "18 months",
                        "risk_reduction": "80%",
                        "compliance_improvement": "75%"
                    }
                }
            },
            "mitre_attack": {
                "tactics": [
                    {
                        "tactic_id": "TA0001",
                        "tactic_name": "Initial Access",
                        "description": "Techniques used to gain initial access to the target system",
                        "techniques": [
                            {
                                "technique_id": "T1190",
                                "technique_name": "Exploit Public-Facing Application",
                                "description": "Adversary attempts to exploit vulnerabilities in public-facing applications",
                                "sub_techniques": [
                                    {
                                        "sub_technique_id": "T1190.001",
                                        "name": "Input Validation",
                                        "description": "Exploitation of input validation vulnerabilities",
                                        "detection": "Monitor application logs for malformed inputs",
                                        "mitigation": "Implement strict input validation",
                                        "implementation": {
                                            "difficulty": "Medium",
                                            "priority": "High",
                                            "estimated_cost": "SAR 25,000",
                                            "required_skills": ["Web Security", "Application Security"]
                                        }
                                    },
                                    {
                                        "sub_technique_id": "T1190.002",
                                        "name": "API Exploitation",
                                        "description": "Exploitation of API vulnerabilities",
                                        "detection": "Monitor API requests for anomalies",
                                        "mitigation": "Implement API security controls",
                                        "implementation": {
                                            "difficulty": "High",
                                            "priority": "High",
                                            "estimated_cost": "SAR 35,000",
                                            "required_skills": ["API Security", "Application Security"]
                                        }
                                    }
                                ],
                                "detection": {
                                    "method": "Monitor for exploitation attempts",
                                    "data_sources": ["WAF Logs", "IDS Alerts", "Application Logs"],
                                    "effectiveness": "High",
                                    "false_positive_rate": "Low",
                                    "implementation_details": {
                                        "tools": ["ModSecurity", "SIEM", "Custom Scripts"],
                                        "configuration": "Enhanced logging and alerting",
                                        "monitoring": "24/7 SOC monitoring"
                                    }
                                },
                                "mitigation": {
                                    "strategy": "Regular patching and security testing",
                                    "controls": ["WAF", "RASP", "Input Validation"],
                                    "implementation_time": "2-4 weeks",
                                    "cost_estimate": "SAR 50,000",
                                    "effectiveness_metrics": {
                                        "attack_prevention": "95%",
                                        "false_positive_rate": "5%",
                                        "maintenance_effort": "Medium"
                                    }
                                }
                            }
                        ],
                        "likelihood": "High",
                        "impact": "Critical",
                        "detection_confidence": 0.8
                    }
                ],
                "attack_patterns": [
                    {
                        "pattern_id": "CAPEC-66",
                        "name": "SQL Injection",
                        "description": "Attacker attempts to modify database queries through malicious input",
                        "phases": ["Reconnaissance", "Exploitation", "Data Exfiltration"],
                        "platforms": ["Web Applications", "Databases"],
                        "severity": "High",
                        "likelihood": "High",
                        "prerequisites": [
                            "Public-facing web application",
                            "Insufficient input validation"
                        ],
                        "mitigations": [
                            "Prepared statements",
                            "Input validation",
                            "WAF implementation"
                        ],
                        "detection_methods": {
                            "primary": {
                                "method": "Pattern matching",
                                "effectiveness": "High",
                                "tools": ["WAF", "SIEM", "IDS"]
                            },
                            "secondary": {
                                "method": "Behavioral analysis",
                                "effectiveness": "Medium",
                                "tools": ["Database Activity Monitoring", "UEBA"]
                            }
                        },
                        "impact_analysis": {
                            "data_confidentiality": "High",
                            "data_integrity": "High",
                            "availability": "Medium",
                            "business_impact": "Critical"
                        }
                    }
                ],
                "kill_chain_phases": [
                    {
                        "phase_name": "Reconnaissance",
                        "description": "Initial information gathering about target systems",
                        "techniques_used": [
                            "Port scanning",
                            "Web application fingerprinting",
                            "Directory enumeration"
                        ],
                        "duration": "1-2 weeks",
                        "indicators": [
                            "Increased scanning activity",
                            "Unusual DNS queries",
                            "Web crawling patterns"
                        ],
                        "detection_opportunities": [
                            "Network IDS alerts",
                            "Web server logs analysis",
                            "DNS query monitoring"
                        ],
                        "countermeasures": {
                            "immediate": [
                                "Enable web server security headers",
                                "Implement rate limiting",
                                "Configure WAF rules"
                            ],
                            "longterm": [
                                "Deploy deception technology",
                                "Implement zero trust architecture",
                                "Enhanced monitoring capabilities"
                            ]
                        }
                    },
                    {
                        "phase_name": "Weaponization",
                        "description": "Preparation of attack payload",
                        "techniques_used": [
                            "Malware development",
                            "Exploit customization",
                            "Social engineering content creation"
                        ],
                        "duration": "1-4 weeks",
                        "indicators": [
                            "New malware variants",
                            "Targeted phishing campaigns",
                            "Custom exploit development"
                        ],
                        "detection_opportunities": [
                            "Threat intelligence feeds",
                            "Malware analysis",
                            "Dark web monitoring"
                        ]
                    }
                ],
                "recommendations": [
                    {
                        "priority": "High",
                        "description": "Implement Web Application Firewall",
                        "implementation": "Deploy ModSecurity WAF with custom rules",
                        "effectiveness": "High",
                        "cost_estimate": "SAR 75,000",
                        "timeframe": "30 days",
                        "dependencies": [
                            "Network Architecture Review",
                            "Security Policy Updates",
                            "Team Training"
                        ],
                        "expected_outcomes": [
                            "90% reduction in common web attacks",
                            "Improved compliance with NCA ECC",
                            "Enhanced monitoring capabilities"
                        ],
                        "implementation_phases": [
                            {
                                "phase": "Planning",
                                "duration": "1 week",
                                "activities": ["Architecture review", "Rule set development"]
                            },
                            {
                                "phase": "Implementation",
                                "duration": "2 weeks",
                                "activities": ["WAF deployment", "Rule testing"]
                            },
                            {
                                "phase": "Optimization",
                                "duration": "1 week",
                                "activities": ["Fine-tuning", "Performance testing"]
                            }
                        ]
                    }
                ],
            }
        }               
def transform_compliance_metrics(compliance_data: Dict) -> Dict:
    """Transform compliance metrics to proper format."""
    try:
        # Ensure each framework has all required fields
        for framework_id, framework in compliance_data.get('frameworks', {}).items():
            framework.setdefault('score', 0)
            framework.setdefault('gap', 100 - framework.get('score', 0))
            framework.setdefault('controls', {
                'implemented': 0,
                'partial': 0,
                'missing': 0
            })
            
            # Ensure percentage values are integers
            framework['score'] = int(framework['score'])
            framework['gap'] = int(framework['gap'])
            
            # Ensure control percentages add up to 100
            controls = framework['controls']
            total = sum(controls.values())
            if total > 0:
                for key in controls:
                    controls[key] = int((controls[key] / total) * 100)
            
        return compliance_data
    except Exception as e:
        logger.error(f"Error transforming compliance metrics: {str(e)}")
        return {
            'frameworks': {
                'nca': {
                    'name': 'NCA Framework',
                    'status': 'Partial',
                    'score': 75,
                    'gap': 25,
                    'priority': 'Medium',
                    'controls': {
                        'implemented': 75,
                        'partial': 15,
                        'missing': 10
                    }
                }
            },
            'status': 'Requires Review',
            'priority': 'Medium'
        }
def analyze_environment_from_content(text: str, file_info: dict = None) -> dict:
    """
    Analyze text content to extract environment and system details.
    """
    import re

    # Initialize environment details
    environment_info = {
        'devices': [],
        'operating_systems': set(),
        'frameworks_and_libraries': set(),
        'programming_languages': set(),
        'databases': set(),
        'servers': set(),
        'cloud_services': set(),
        'containerization': [],
        'network_components': set()
    }

    # Operating Systems patterns
    os_patterns = {
        'windows': r'(?i)(windows\s*(server)?\s*(20\d{2}|xp|vista|[78]|10|11))',
        'linux': r'(?i)(ubuntu|debian|centos|rhel|red\s*hat|fedora|kali|linux)\s*\d*\.?\d*',
        'macos': r'(?i)(macos|mac\s*os\s*x|darwin)\s*\d*\.?\d*'
    }

    # Programming Languages
    lang_patterns = {
        'python': r'(?i)(python|\.py\b|\bpip\b|requirements\.txt)',
        'java': r'(?i)(java\b|\.jar\b|\.java\b|springframework)',
        'javascript': r'(?i)(javascript|node\.js|\.js\b|npm|package\.json)',
        'php': r'(?i)(php[5-8]?|\.php\b)',
        'csharp': r'(?i)(c#|\.cs\b|dotnet|\.net)',
        'golang': r'(?i)(golang|\.go\b)'
    }

    # Frameworks and Libraries
    framework_patterns = {
        'web_frameworks': r'(?i)(django|flask|spring|laravel|express|rails)',
        'ml_frameworks': r'(?i)(tensorflow|pytorch|scikit-learn|keras)',
        'ui_frameworks': r'(?i)(react|angular|vue|bootstrap|tailwind)'
    }

    # Database Systems
    db_patterns = {
        'sql': r'(?i)(mysql|postgresql|mariadb|sqlite|sql\s*server)',
        'nosql': r'(?i)(mongodb|redis|cassandra|elasticsearch)',
        'graph': r'(?i)(neo4j|orientdb|janusgraph)'
    }

    # Server and Infrastructure
    server_patterns = {
        'web_servers': r'(?i)(apache|nginx|iis|tomcat)',
        'app_servers': r'(?i)(gunicorn|uwsgi|passenger)',
        'cloud': r'(?i)(aws|amazon|azure|gcp|google\s*cloud)',
        'containers': r'(?i)(docker|kubernetes|k8s|container|pod)'
    }

    # Analyze text content
    # Operating Systems
    for os_name, pattern in os_patterns.items():
        matches = re.findall(pattern, text)
        if matches:
            environment_info['operating_systems'].update(matches)

    # Programming Languages
    for lang, pattern in lang_patterns.items():
        if re.search(pattern, text):
            environment_info['programming_languages'].add(lang)

    # Frameworks
    for framework_type, pattern in framework_patterns.items():
        matches = re.findall(pattern, text)
        if matches:
            environment_info['frameworks_and_libraries'].update(matches)

    # Databases
    for db_type, pattern in db_patterns.items():
        matches = re.findall(pattern, text)
        if matches:
            environment_info['databases'].update(matches)

    # Servers and Infrastructure
    for server_type, pattern in server_patterns.items():
        matches = re.findall(pattern, text)
        if matches:
            if server_type == 'cloud':
                environment_info['cloud_services'].update(matches)
            elif server_type == 'containers':
                environment_info['containerization'].extend(matches)
            else:
                environment_info['servers'].update(matches)

    # Network Components
    network_patterns = {
        r'(?i)port\s*(\d+)': 'ports',
        r'(?i)(localhost|127\.0\.0\.1)': 'localhost',
        r'(?i)https?://[^\s<>"]+': 'urls',
        r'(?i)subnet\s*mask': 'network_config',
        r'(?i)firewall': 'security_components'
    }

    for pattern, component_type in network_patterns.items():
        matches = re.findall(pattern, text)
        if matches:
            environment_info['network_components'].add(f"{component_type}: {', '.join(str(m) for m in matches)}")

    # Device Information
    device_patterns = {
        'servers': r'(?i)(server|instance|node)\s*:\s*([^\n]+)',
        'endpoints': r'(?i)(endpoint|client|device)\s*:\s*([^\n]+)',
        'hardware': r'(?i)(cpu|processor|ram|memory|disk)\s*:\s*([^\n]+)'
    }

    for device_type, pattern in device_patterns.items():
        matches = re.findall(pattern, text)
        if matches:
            for match in matches:
                environment_info['devices'].append({
                    'type': device_type,
                    'identifier': match[1].strip() if len(match) > 1 else match[0].strip()
                })

    # Convert sets to sorted lists for better display
    for key in environment_info:
        if isinstance(environment_info[key], set):
            environment_info[key] = sorted(list(environment_info[key]))

    # Add scope information
    environment_info['scope'] = {
        'assessment_type': 'Security Vulnerability Analysis',
        'target_type': determine_target_type(environment_info),
        'components_analyzed': len(file_info['files']) if file_info and 'files' in file_info else 0,
        'environment_type': determine_environment_type(environment_info)
    }

    return environment_info

def determine_target_type(env_info: dict) -> str:
    """Determine the type of target based on environment information."""
    if env_info['cloud_services']:
        return 'Cloud Application'
    elif env_info['containerization']:
        return 'Containerized Application'
    elif any(srv for srv in env_info['servers'] if 'web' in srv.lower()):
        return 'Web Application'
    elif env_info['databases']:
        return 'Database Application'
    return 'General Application'

def determine_environment_type(env_info: dict) -> str:
    """Determine the type of environment based on detected components."""
    if any('prod' in str(item).lower() for item in env_info['servers']):
        return 'Production'
    elif any('dev' in str(item).lower() for item in env_info['servers']):
        return 'Development'
    elif any('test' in str(item).lower() for item in env_info['servers']):
        return 'Testing'
    return 'Unknown'

@app.route('/api/report/<session_id>')
@login_required
@async_to_sync
async def generate_report(session_id):
    try:
        logger.info(f"Starting AI-enhanced report generation for session {session_id}")
        
        # Get OpenAI API key from environment
        api_key = os.getenv('OPENAI_API_KEY')
        if not api_key:
            raise ValueError("OpenAI API key not found in environment variables")
        
        # Get session and analysis data
        session = Session.query.filter_by(id=session_id, user_id=current_user.id).first()
        if not session:
            return jsonify({'error': 'Session not found'}), 404

        analysis = Analysis.query.filter_by(session_id=session_id).first()
        if not analysis:
            return jsonify({'error': 'No analysis found for this session'}), 404

        logger.info(f"Found analysis record: {analysis.id} for session {session_id}")

        # Process analysis data
        analysis_data = {
            'vulnerability_type': analysis.vulnerability_type or 'Unknown',
            'severity': analysis.severity or 'Low',
            'confidence': float(analysis.confidence or 0.5),
            'impact': analysis.impact or 'No impact information available',
            'cwe_id': analysis.cwe_id or 'N/A',
            'cvss_score': float(analysis.cvss_score or 0.0),
            'evidence': json.loads(analysis.evidence) if analysis.evidence else [],
            'recommendations': json.loads(analysis.recommendations) if analysis.recommendations else [],
            'affected_components': json.loads(analysis.affected_components) if analysis.affected_components else [],
            'attack_vectors': json.loads(analysis.attack_vectors) if analysis.attack_vectors else [],
            'extracted_text': analysis.extracted_text,
            'file_info': json.loads(analysis.file_info) if analysis.file_info else {}
        }

        # Initialize report AI assistant with API key
        report_ai = ReportGenerationAssistant(api_key=api_key)

        # Analyze environment from the extracted text
        environment_info = analyze_environment_from_content(
            analysis.extracted_text,
            json.loads(analysis.file_info) if analysis.file_info else None
        )
        logger.info("Successfully analyzed environment information")
        
        try:
            # Get AI-generated report metrics
            report_metrics = await report_ai.analyze_for_report(analysis_data)
            if not report_metrics:
                report_metrics = report_ai._get_default_metrics()
            
            compliance_metrics = transform_compliance_metrics(report_metrics.get('compliance', {}))
            logger.info("Successfully generated AI-enhanced report metrics")
            
        except Exception as e:
            logger.error(f"Error generating report metrics: {str(e)}")
            report_metrics = report_ai._get_default_metrics()
            compliance_metrics = transform_compliance_metrics(report_metrics.get('compliance', {}))

        # Calculate risk metrics
        risk_metrics = calculate_risk_metrics(analysis)
        
        # Calculate business impact
        business_impact = calculate_business_impact(analysis)
        
        # Add component counts for executive summary
        environment_summary = {
            'total_components': sum([
                len(environment_info.get('operating_systems', [])),
                len(environment_info.get('programming_languages', [])),
                len(environment_info.get('frameworks_and_libraries', [])),
                len(environment_info.get('databases', [])),
                len(environment_info.get('servers', [])),
                len(environment_info.get('cloud_services', [])),
                len(environment_info.get('containerization', [])),
                len(environment_info.get('network_components', []))
            ]),
            'critical_components': len([
                component for component in environment_info.get('devices', [])
                if any(critical in component.get('identifier', '').lower() 
                      for critical in ['prod', 'critical', 'secure', 'sensitive'])
            ]),
            'environment_type': environment_info['scope']['environment_type'],
            'target_type': environment_info['scope']['target_type']
        }

        # Prepare template data
        template_data = {
            'session': session,
            'current_user': current_user,
            'analysis': analysis_data,
            'risk_metrics': risk_metrics,
            'business_impact': business_impact,
            'compliance': compliance_metrics,
            'resources': report_metrics.get('resources', {}),
            'mitre_attack': report_metrics.get('mitre_attack', {}),
            'environment_info': environment_info,
            'environment_summary': environment_summary,
            'now': datetime.now(timezone.utc),
            'report_date': datetime.now().strftime('%Y-%m-%d'),
            'report_id': f"VAPT-{session_id[:8].upper()}",
            'metadata': {
                'author': current_user.username,
                'classification': 'Confidential',
                'version': '1.0',
                'generated_at': datetime.now(timezone.utc).isoformat()
            }
        }

        # Validate template data
        template_data = validate_template_data(template_data)
        try:
            # Configure PDF generation
            font_config = FontConfiguration()
            html = render_template('professional_report.html', **template_data)
            
            # Create reports directory if it doesn't exist
            reports_dir = Path(current_app.config['UPLOAD_FOLDER']) / 'reports'
            reports_dir.mkdir(exist_ok=True)
            
            css = CSS(string='''
                @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');
                @page { 
                    size: letter; 
                    margin: 2.5cm; 
                    @top-center { 
                        content: "Security Assessment Report"; 
                        font-family: Inter, sans-serif;
                    }
                    @bottom-center { 
                        content: "Page " counter(page) " of " counter(pages);
                        font-family: Inter, sans-serif;
                    }
                }
                body { 
                    font-family: Inter, sans-serif;
                    line-height: 1.6;
                }
                .page-break { 
                    page-break-after: always; 
                }
                pre {
                    white-space: pre-wrap;
                    word-wrap: break-word;
                    font-family: monospace;
                }
                .code-block { 
                    background: #1a1a1a; 
                    padding: 1em; 
                    border-radius: 4px;
                    font-family: monospace;
                    white-space: pre-wrap;
                    word-wrap: break-word;
                }
                table {
                    width: 100%;
                    border-collapse: collapse;
                    margin: 1em 0;
                }
                th, td {
                    border: 1px solid #2a2a2a;
                    padding: 8px;
                    text-align: left;
                }
                th {
                    background-color: #1a1a1a;
                }
                img {
                    max-width: 100%;
                    height: auto;
                    border-radius: 4px;
                    margin: 1em 0;
                }
                
                /* Enhanced styling for vulnerability sections */
                .vulnerability-section {
                    border: 1px solid #2a2a2a;
                    border-radius: 8px;
                    padding: 1.5em;
                    margin-bottom: 1.5em;
                }
                
                .severity-critical {
                    border-left: 4px solid #ef4444;
                }
                
                .severity-high {
                    border-left: 4px solid #f97316;
                }
                
                .severity-medium {
                    border-left: 4px solid #eab308;
                }
                
                .severity-low {
                    border-left: 4px solid #22c55e;
                }
                /* MITRE ATT&CK Section Styling */
                .mitre-section {
                    margin: 2em 0;
                    padding: 1.5em;
                    background: #f8f9fa;
                    border-radius: 8px;
                    border: 1px solid #dee2e6;
                }

                .tactic-card {
                    margin: 1em 0;
                    padding: 1em;
                    background: white;
                    border-radius: 4px;
                    box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                }

                .technique-list {
                    margin-left: 1.5em;
                }

                .technique-item {
                    margin: 0.5em 0;
                }

                .kill-chain-phase {
                    padding: 0.5em;
                    background: #e9ecef;
                    border-radius: 4px;
                    margin: 0.5em 0;
                }

                .mitre-id {
                    font-family: monospace;
                    background: #e9ecef;
                    padding: 0.2em 0.4em;
                    border-radius: 3px;
                }
                /* Enhanced metrics visualization */
                .metric-card {
                    background: #1a1a1a;
                    border-radius: 8px;
                    padding: 1em;
                    margin-bottom: 1em;
                }
                
                .metric-value {
                    font-size: 1.5em;
                    font-weight: bold;
                    margin-bottom: 0.5em;
                }
                
                .progress-bar {
                    height: 8px;
                    border-radius: 4px;
                    background: #2a2a2a;
                    overflow: hidden;
                }
                
                .progress-value {
                    height: 100%;
                    transition: width 0.3s ease;
                }
            ''', font_config=font_config)
            
            # Generate PDF
            pdf = HTML(string=html).write_pdf(
                stylesheets=[css],
                font_config=font_config
            )
            
            # Save report with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'Security_Assessment_{session_id}_{timestamp}.pdf'
            report_path = reports_dir / filename
            
            with open(report_path, 'wb') as f:
                f.write(pdf)
            
            logger.info(f"Successfully generated report: {filename}")
            
            # Prepare response
            response = make_response(pdf)
            response.headers['Content-Type'] = 'application/pdf'
            response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
            
            return response

        except Exception as template_error:
            logger.error(f"Template rendering error: {str(template_error)}")
            return jsonify({
                'error': 'Failed to generate report',
                'details': str(template_error)
            }), 500

    except Exception as e:
        logger.error(f"Report generation error: {str(e)}")
        return jsonify({
            'error': 'Failed to generate report',
            'details': str(e)
        }), 500
def validate_template_data(template_data):
    """Validate and sanitize template data before rendering."""
    try:
        # Ensure resources dictionary has required keys
        required_keys = ['immediate', 'shortterm', 'longterm']
        for key in required_keys:
            if key not in template_data['resources']:
                template_data['resources'][key] = {
                    'timeline': '30 days',
                    'cost': '$0',
                    'staff': 0,
                    'actions': []
                }

        # Ensure recommendations exist
        if not template_data['analysis'].get('recommendations'):
            template_data['analysis']['recommendations'] = [
                'Implement security controls',
                'Enhance monitoring',
                'Regular assessment'
            ]

        # Validate numerical values
        template_data['analysis']['confidence'] = float(template_data['analysis'].get('confidence', 0.5))
        template_data['analysis']['cvss_score'] = float(template_data['analysis'].get('cvss_score', 5.0))

        # Ensure all required keys exist in business_impact
        if 'business_impact' not in template_data:
            template_data['business_impact'] = calculate_business_impact(template_data['analysis'])

        # Ensure all required keys exist in risk_metrics
        if 'risk_metrics' not in template_data:
            template_data['risk_metrics'] = calculate_risk_metrics(template_data['analysis'])

        # Ensure all required keys exist in compliance
        if 'compliance' not in template_data:
            template_data['compliance'] = calculate_compliance_metrics(template_data['analysis'])

        return template_data

    except Exception as e:
        logger.error(f"Template data validation error: {str(e)}")
        raise
@app.route('/api/stats')
@login_required
def get_stats():
    try:
        analyses = Analysis.query.join(Session).filter(
            Session.user_id == current_user.id
        ).all()
        
        stats = {
            'total': len(analyses),
            'by_severity': {},
            'by_type': {},
            'cvss_distribution': {
                'critical': 0,  # 9.0-10.0
                'high': 0,      # 7.0-8.9
                'medium': 0,    # 4.0-6.9
                'low': 0        # 0.1-3.9
            },
            'affected_components': {},
            'most_common_vulnerabilities': []
        }
        
        # Calculate statistics
        for analysis in analyses:
            # Severity stats
            stats['by_severity'][analysis.severity] = \
                stats['by_severity'].get(analysis.severity, 0) + 1
            
            # Vulnerability type stats
            stats['by_type'][analysis.vulnerability_type] = \
                stats['by_type'].get(analysis.vulnerability_type, 0) + 1
            
            # CVSS score distribution
            if analysis.cvss_score >= 9.0:
                stats['cvss_distribution']['critical'] += 1
            elif analysis.cvss_score >= 7.0:
                stats['cvss_distribution']['high'] += 1
            elif analysis.cvss_score >= 4.0:
                stats['cvss_distribution']['medium'] += 1
            else:
                stats['cvss_distribution']['low'] += 1
                
            # Affected components stats
            if analysis.affected_components:
                components = json.loads(analysis.affected_components)
                for component in components:
                    stats['affected_components'][component] = \
                        stats['affected_components'].get(component, 0) + 1
        
        # Get most common vulnerabilities
        sorted_vulns = sorted(
            stats['by_type'].items(),
            key=lambda x: x[1],
            reverse=True
        )
        stats['most_common_vulnerabilities'] = sorted_vulns[:5]
        
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f"Stats error: {str(e)}")
        return jsonify({'error': 'Failed to get statistics'}), 500
@app.route('/api/create_session', methods=['POST'])
@login_required
def create_session():
    try:
        data = request.get_json()
        company_name = data.get('company_name')
        
        # Create new session
        session_id = str(uuid.uuid4())
        new_session = Session(
            id=session_id,
            user_id=current_user.id,
            company_name=company_name
        )
        db.session.add(new_session)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'session_id': session_id
        })
    except Exception as e:
        logger.error(f"Error creating session: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to create session'
        }), 500
@app.route('/api/session/<session_id>')
@login_required
def get_session(session_id):
    try:
        logger.info(f"Fetching session {session_id} for user {current_user.id}")
        
        # Fetch session with analysis
        session = Session.query.filter_by(
            id=session_id,
            user_id=current_user.id
        ).first()
        
        if not session:
            logger.error(f"Session {session_id} not found")
            return jsonify({
                'success': False,
                'error': 'Session not found'
            }), 404

        # Get the latest analysis for this session
        analysis = Analysis.query.filter_by(
            session_id=session_id
        ).order_by(Analysis.created_at.desc()).first()

        if not analysis:
            logger.error(f"No analysis found for session {session_id}")
            return jsonify({
                'success': False,
                'error': 'No analysis found for this session'
            }), 404

        # Prepare analysis data
        analysis_data = {
            'vulnerability_type': analysis.vulnerability_type or 'Unknown',
            'severity': analysis.severity or 'Low',
            'confidence': float(analysis.confidence or 0.5),
            'impact': analysis.impact or 'No impact information available',
            'cwe_id': analysis.cwe_id or 'N/A',
            'cvss_score': float(analysis.cvss_score or 0.0),
            'recommendations': json.loads(analysis.recommendations) if analysis.recommendations else [],
            'evidence': json.loads(analysis.evidence) if analysis.evidence else [],
            'affected_components': json.loads(analysis.affected_components) if analysis.affected_components else [],
            'created_at': analysis.created_at.isoformat() if analysis.created_at else None
        }

        logger.info(f"Successfully retrieved analysis for session {session_id}")
        
        return jsonify({
            'success': True,
            'session_id': session_id,
            'company_name': session.company_name,
            'analysis': analysis_data
        })

    except Exception as e:
        logger.error(f"Error fetching session data: {str(e)}")
        return jsonify({
            'success': False,
            'error': 'Failed to fetch session data'
        }), 500
        
        
@app.route('/analytics_dashboard')  # Changed from /analytics
@login_required
def analytics_dashboard():  # This is the function name
    try:
        return render_template('analytics_dashboard.html', current_user=current_user)
    except Exception as e:
        current_app.logger.error(f"Analytics dashboard error: {str(e)}")
        return redirect(url_for('dashboard'))

@app.route('/api/analytics/<company_name>')
@login_required
def get_analytics(company_name):
    try:
        # analytics data logic here
        analytics_data = {
            'securityScore': 85.2,
            'criticalVulnerabilities': 7,
            'avgResponseTime': 4.2,
            'riskAssessment': 'Medium',
        }
        companies = [
            {'id': 1, 'name': 'TechCorp Solutions'},
            {'id': 2, 'name': 'SecureNet Systems'},
            {'id': 3, 'name': 'DataGuard Inc'},
            # Add more companies or fetch from your database
        ]
        
        return jsonify(analytics_data)
    except Exception as e:
        current_app.logger.error(f"Analytics API error: {str(e)}")
        return jsonify({'error': str(e)}), 500
    
# Update the get_companies route
@app.route('/api/companies')
@login_required
def get_companies():
    try:
        # Get unique companies with their latest session
        latest_sessions = db.session.query(
            Session.company_name,
            db.func.max(Session.created_at).label('latest_date')
        ).filter(
            Session.user_id == current_user.id,
            Session.status == 'active',
            Session.company_name.isnot(None),
            Session.company_name != ''
        ).group_by(
            Session.company_name
        ).all()

        # Get full session details for each latest session
        companies = []
        for company_name, latest_date in latest_sessions:
            session = Session.query.filter_by(
                user_id=current_user.id,
                company_name=company_name,
                created_at=latest_date
            ).first()

            if session:
                companies.append({
                    'id': str(session.id),
                    'name': session.company_name,
                    'created_at': session.created_at.isoformat(),
                    'last_analysis': session.latest_analysis.created_at.isoformat() if session.latest_analysis else None,
                    'metrics': {
                        'vulnerabilities': len(session.analyses) if session.analyses else 0,
                        'last_scan': session.latest_analysis.created_at.isoformat() if session.latest_analysis else None
                    }
                })

        # Sort companies by name
        companies.sort(key=lambda x: x['name'])

        return jsonify({
            'success': True,
            'companies': companies
        })

    except Exception as e:
        logger.error(f"Error fetching companies: {str(e)}")
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500
        
@app.route('/api/recent-activity/<company_name>')
@login_required
def get_recent_activity(company_name):
    try:
        # Get all sessions for this company
        sessions = Session.query.filter(
            Session.user_id == current_user.id,
            Session.company_name == company_name,
            Session.status == 'active'
        ).all()

        if not sessions:
            return jsonify({
                'success': False,
                'error': 'Company not found'
            }), 404

        session_ids = [session.id for session in sessions]

        # Get recent analyses across all sessions for this company
        analyses = Analysis.query.filter(
            Analysis.session_id.in_(session_ids)
        ).order_by(
            Analysis.created_at.desc()
        ).limit(10).all()  # Increased limit to show more activities

        activity_list = []
        now = datetime.now(timezone.utc)

        for analysis in analyses:
            # Ensure created_at is timezone-aware
            created_at = analysis.created_at
            if created_at.tzinfo is None:
                created_at = created_at.replace(tzinfo=timezone.utc)

            # Calculate time difference
            time_diff = now - created_at
            
            if time_diff.total_seconds() < 60:
                time_ago = 'just now'
            elif time_diff.total_seconds() < 3600:
                minutes = int(time_diff.total_seconds() / 60)
                time_ago = f'{minutes}m ago'
            elif time_diff.total_seconds() < 86400:
                hours = int(time_diff.total_seconds() / 3600)
                time_ago = f'{hours}h ago'
            else:
                days = int(time_diff.total_seconds() / 86400)
                time_ago = f'{days}d ago'

            # Get affected components
            affected_components = json.loads(analysis.affected_components) if analysis.affected_components else []
            
            activity_list.append({
                'id': str(analysis.id),
                'title': 'Security Analysis Completed',
                'severity': analysis.severity or 'Medium',
                'description': f"Found Multiple Vulnerabilities: {analysis.vulnerability_type}" if analysis.vulnerability_type else "Analysis completed",
                'timestamp': created_at.isoformat(),
                'time_ago': time_ago,
                'metrics': {
                    'critical_count': analysis.cvss_score if analysis.cvss_score else 0,
                    'components': len(affected_components),
                    'score': analysis.confidence if analysis.confidence else 0
                },
                'components': affected_components[:5]  # Show first 5 components
            })

        return jsonify({
            'success': True,
            'activities': activity_list
        })

    except Exception as e:
        logger.error(f"Error fetching recent activity: {str(e)}")
        return jsonify({'success': False, 'error': str(e)}), 500
    
# Helper function to format time ago
def format_time_ago(timestamp):
    now = datetime.now(timezone.utc)
    diff = now - timestamp
    
    seconds = diff.total_seconds()
    if seconds < 60:
        return 'just now'
    elif seconds < 3600:
        minutes = int(seconds / 60)
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
    elif seconds < 86400:
        hours = int(seconds / 3600)
        return f"{hours} hour{'s' if hours != 1 else ''} ago"
    else:
        days = int(seconds / 86400)
        return f"{days} day{'s' if days != 1 else ''} ago"
        
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/refresh-csrf')
def refresh_csrf():
    return jsonify({'csrf_token': generate_csrf()})

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    if request.is_json:
        return jsonify({'error': 'Resource not found'}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    if request.is_json:
        return jsonify({'error': 'Internal server error'}), 500
    return render_template('500.html'), 500

def perform_database_migration():
    with app.app_context():
        try:
            # Check if column exists
            inspector = inspect(db.engine)
            if 'analysis_session_id' not in [c['name'] for c in inspector.get_columns('analyses')]:
                # Use text() to properly declare the SQL
                sql = text('ALTER TABLE analyses ADD COLUMN analysis_session_id INTEGER REFERENCES analysis_sessions(id)')
                db.session.execute(sql)
                db.session.commit()
                logger.info("Successfully added analysis_session_id column")
            if 'company_name' not in [c['name'] for c in inspector.get_columns('sessions')]:
                sql = text('ALTER TABLE sessions ADD COLUMN company_name VARCHAR(255)')
                db.session.execute(sql)
                db.session.commit()
                logger.info("Successfully added company_name column to sessions table")
                

        except Exception as e:
            logger.error(f"Migration error: {str(e)}")
            db.session.rollback()
            raise
        

def init_db():
    with app.app_context():
        try:
            # Drop all tables
            db.drop_all()
            logger.info("Dropped all existing tables")
            
            # Create all tables
            db.create_all()
            logger.info("Created all tables")
            
            # Create test user
            test_user = User(username='test_user')
            test_user.set_password('password123')
            
            # Create admin user
            admin_user = User(username='admin')
            admin_user.set_password('admin')
            
            # Add users to session
            db.session.add(test_user)
            db.session.add(admin_user)
            
            try:
                db.session.commit()
                logger.info('Successfully created test and admin users')
            except Exception as e:
                db.session.rollback()
                logger.error(f'Error creating users: {str(e)}')
                raise
                
        except Exception as e:
            logger.error(f'Database initialization error: {str(e)}')
            raise

def init_app():
    """Initialize the application."""
    try:
        # Create necessary directories
        for directory in ['instance', 'uploads', 'uploads/temp', 'uploads/reports', 'logs']:
            path = BASE_DIR / directory
            path.mkdir(parents=True, exist_ok=True)
            logger.info(f"Created directory: {directory}")

        # Initialize database
        init_db()
        logger.info('Application initialized successfully')
        
    except Exception as e:
        logger.error(f"Initialization error: {str(e)}")
        raise

if __name__ == '__main__':
    try:
        # Log startup information
        logger.info(f"Starting server with upload folder: {UPLOAD_FOLDER}")
        logger.info(f"Database path: {Config.SQLALCHEMY_DATABASE_URI}")
        
        # Initialize the application
        init_app()
        
        # Run the application
        app.run(
            host='0.0.0.0',
            port=5001,
            debug=True
        )
        
    except Exception as e:
        logger.error(f"Server startup error: {str(e)}")
