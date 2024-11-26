# AI-VARA (Vulnerability Assessment Report Automation) tool

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-v3.8+-blue.svg)
![Flask](https://img.shields.io/badge/flask-v2.0+-green.svg)
![Status](https://img.shields.io/badge/status-active-success.svg)

VARA is an advanced security analysis platform that combines machine learning and pattern-based analysis to identify vulnerabilities in code and systems. It provides comprehensive security assessments with detailed reporting and real-time monitoring capabilities.

## 🌟 Features

- **Multi-Engine Analysis**
  - Pattern-based vulnerability detection
  - ML-powered security analysis using LLaMA and LoRA models
  - Real-time code and text analysis
  - Comprehensive vulnerability assessment

- **Advanced Reporting**
  - Detailed vulnerability reports with CVSS scoring
  - MITRE ATT&CK framework integration
  - Compliance mapping (NCA, ISO27001)
  - Executive-level security metrics
  - Risk assessment visualization

- **Security Features**
  - User authentication and authorization
  - Session management
  - Secure file handling
  - CSRF protection
  - Input validation and sanitization

- **Analytics Dashboard**
  - Real-time security metrics
  - Vulnerability trending
  - Risk assessment visualization
  - Compliance status tracking

## 🚀 Getting Started

### Prerequisites

- Python 3.8+
- pip
- Virtual environment (recommended)
- Google Cloud Vision API credentials
- OpenAI API key

### Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/vara.git
cd vara
```

2. Create and activate virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
```bash
cp .env.example .env
```
Edit `.env` file with your configuration:
```
SECRET_KEY=your-secret-key
OPENAI_API_KEY=your-openai-api-key
GOOGLE_CREDENTIALS=path/to/your/google-credentials.json
```

5. Initialize the database:
```bash
flask db upgrade
```

6. Run the application:
```bash
python app.py
```

The application will be available at `http://localhost:5001`

## 🏗️ Project Structure

```
vara/
├── analyzers/
│   ├── ml_analyzers.py
│   ├── pattern_analyzer.py
│   └── base.py
├── static/
│   ├── css/
│   └── js/
├── templates/
│   ├── analytics_dashboard.html
│   ├── base.html
│   ├── dashboard.html
│   └── professional_report.html
├── utils/
│   └── config.py
├── app.py
├── requirements.txt
└── README.md
```

## 🛠️ Technologies Used

- **Backend**
  - Flask (Web Framework)
  - SQLAlchemy (ORM)
  - PyTorch (ML Models)
  - OpenAI API (LLM Integration)
  - Google Cloud Vision API (Image Analysis)

- **Frontend**
  - TailwindCSS (Styling)
  - Alpine.js (JavaScript Framework)
  - Chart.js (Data Visualization)

- **Security**
  - Flask-Login (Authentication)
  - Flask-WTF (CSRF Protection)
  - Werkzeug (Password Hashing)

## 📖 API Documentation

### Authentication Endpoints

```bash
POST /login
POST /register
GET /logout
```

### Analysis Endpoints

```bash
POST /api/analyze-multiple
POST /upload_image
GET /api/session/<session_id>
GET /api/analytics/<company_name>
```

### Report Endpoints

```bash
GET /api/report/<session_id>
GET /api/stats
```

## 🔒 Security Considerations

- All passwords are hashed using Werkzeug's security functions
- CSRF protection is enabled for all forms
- File uploads are validated and sanitized
- Session management with secure cookie handling
- Input validation and sanitization for all user inputs
- Rate limiting on sensitive endpoints
- Secure file handling with type checking

## 🤝 Contributing

We welcome contributions to VARA! Please follow these steps:

1. Fork the repository
2. Create a new branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

Please ensure your PR adheres to:
- Consistent coding style
- Comprehensive documentation
- Adequate test coverage
- Security best practices

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- OpenAI for and LLM capabilities
- Google Cloud Vision for image analysis
- MITRE ATT&CK framework for security mapping
- The Flask and Python communities

## 📞 Contact

For support or queries:
- Email: salman.alqasmah@outlook.com
- Issue Tracker: https://github.com/salmanalqasmah/vara/issues

## 🔄 Roadmap

- [ ] Integration with additional ML models
- [ ] Enhanced compliance reporting
- [ ] API rate limiting
- [ ] Container vulnerability scanning
- [ ] Cloud infrastructure analysis
- [ ] Mobile application security scanning
- [ ] Real-time threat intelligence integration
- [ ] Custom rule engine development
