# Add these imports at the top
from transformers import LlamaForCausalLM, LlamaTokenizer
from peft import PeftModel, LoraConfig, get_peft_model

# Add ML configuration
class MLConfig:
    LLAMA_MODEL_PATH = os.path.join(BASE_DIR, 'models', 'Llama-3.2-3B-Instruct', 'original')
    LORA_PATH = os.path.join(BASE_DIR, 'models', 'lora-adapter')
    DEVICE = "cpu"

# Initialize ML models
def initialize_ml_models():
    try:
        logger.info("Initializing ML models...")
        
        # Initialize LLaMA
        tokenizer = LlamaTokenizer.from_pretrained(
            MLConfig.LLAMA_MODEL_PATH,
            local_files_only=True
        )
        
        model = LlamaForCausalLM.from_pretrained(
            MLConfig.LLAMA_MODEL_PATH,
            local_files_only=True,
            torch_dtype=torch.float32,
            low_cpu_mem_usage=True,
            device_map=None
        ).to(MLConfig.DEVICE)
        
        # Initialize LoRA adapter
        config = LoraConfig.from_pretrained(MLConfig.LORA_PATH)
        lora_model = get_peft_model(model, config)
        
        logger.info("ML models initialized successfully")
        return model, lora_model, tokenizer
    except Exception as e:
        logger.error(f"Failed to initialize ML models: {e}")
        return None, None, None

# Add ML analysis function
async def analyze_with_ml(text: str, model, lora_model, tokenizer):
    try:
        # LLaMA analysis
        llama_prompt = f"""[INST] Analyze this text for security vulnerabilities:
        {text}
        Focus on SQL injection and privilege escalation.
        [/INST]"""
        
        inputs = tokenizer(llama_prompt, return_tensors="pt", truncation=True)
        with torch.no_grad():
            outputs = model.generate(
                **inputs,
                max_new_tokens=200,
                temperature=0.7,
                do_sample=True
            )
        llama_result = tokenizer.decode(outputs[0], skip_special_tokens=True)
        
        # LoRA analysis
        lora_prompt = f"""[INST] Analyze for vulnerabilities:
        {text}
        [/INST]"""
        
        inputs = tokenizer(lora_prompt, return_tensors="pt", truncation=True)
        with torch.no_grad():
            outputs = lora_model.generate(
                **inputs,
                max_new_tokens=100,
                temperature=0.7,
                do_sample=True
            )
        lora_result = tokenizer.decode(outputs[0], skip_special_tokens=True)
        
        # Combine results
        if "SQL" in llama_result.upper() or "SQL" in lora_result.upper():
            return {
                'vulnerability_type': 'SQL Injection',
                'severity': 'Critical',
                'confidence': 0.9,
                'impact': 'High risk of unauthorized database access',
                'recommendations': [
                    'Use parameterized queries',
                    'Implement input validation',
                    'Enable WAF protection',
                    'Use ORM framework'
                ]
            }
        
        return {
            'vulnerability_type': 'Pattern Analysis',
            'severity': 'Medium',
            'confidence': 0.75,
            'impact': 'Potential security vulnerabilities detected',
            'recommendations': [
                'Implement input validation',
                'Use parameterized queries',
                'Enable security monitoring'
            ]
        }
    except Exception as e:
        logger.error(f"ML analysis error: {e}")
        return None
class EnhancedMLAnalyzer(SecurityAnalyzer):
    def __init__(self, model, tokenizer):
        self.model = model
        self.tokenizer = tokenizer
        self.max_length = 512
        self.device = "cuda" if torch.cuda.is_available() else "cpu"
        
    async def analyze(self, content: str) -> Optional[SecurityAnalysisResult]:
        try:
            prompt = self._create_security_prompt(content)
            
            inputs = self.tokenizer(
                prompt,
                return_tensors="pt",
                max_length=self.max_length,
                truncation=True,
                padding=True
            ).to(self.device)
            
            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=256,
                    temperature=0.7,
                    num_return_sequences=1,
                    do_sample=True
                )
            
            result = self.tokenizer.decode(outputs[0], skip_special_tokens=True)
            return self._parse_ml_output(result, content)
            
        except Exception as e:
            logger.error(f"ML analysis error: {str(e)}")
            return None
    
    def cleanup(self):
        if hasattr(self, 'model'):
            self.model.cpu()
            torch.cuda.empty_cache()
# Update the upload_image route
@app.route('/upload_image', methods=['POST'])
@login_required
@run_async
async def upload_image():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400

        file = request.files['file']
        if not file.filename:
            return jsonify({'error': 'No file selected'}), 400

        # Save file and extract text
        session_id = str(uuid.uuid4())
        file_path = save_file(current_user.username, session_id, file)
        if not file_path:
            return jsonify({'error': 'Invalid file type'}), 400

        # Extract text
        try:
            if file_path.lower().endswith('.txt'):
                with open(file_path, 'r') as f:
                    extracted_text = f.read()
            else:
                extracted_text = extract_text_with_google_vision(file_path)

            if not extracted_text:
                return jsonify({'error': 'No text could be extracted'}), 400

            logger.info(f"Extracted text: {extracted_text}")

            # Perform ML analysis
            ml_result = await analyze_with_ml(extracted_text, model, lora_model, tokenizer)
            
            # Combine with pattern analysis
            pattern_result = analyze_patterns(extracted_text)
            
            # Use ML result if available, otherwise fall back to pattern analysis
            analysis_result = ml_result if ml_result else pattern_result
            analysis_result['analysis_sources'] = {
                'pattern': True,
                'lora': ml_result is not None,
                'llama': ml_result is not None
            }

            # Save results
            new_session = Session(id=session_id, user_id=current_user.id)
            db.session.add(new_session)

            new_analysis = Analysis(
                session_id=session_id,
                image_path=file_path,
                extracted_text=extracted_text,
                vulnerability_type=analysis_result['vulnerability_type'],
                confidence=analysis_result['confidence'],
                severity=analysis_result['severity'],
                impact=analysis_result['impact'],
                recommendations=json.dumps(analysis_result['recommendations']),
                analysis_sources=json.dumps(analysis_result['analysis_sources'])
            )
            db.session.add(new_analysis)
            db.session.commit()

            return jsonify({
                'success': True,
                'session_id': session_id,
                'analysis': analysis_result,
                'extracted_text': extracted_text
            })

        except Exception as e:
            logger.error(f"Analysis error: {str(e)}")
            return jsonify({'error': 'Analysis failed'}), 500

    except Exception as e:
        logger.error(f"Upload error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Initialize ML models at startup
model, lora_model, tokenizer = None, None, None
with app.app_context():
    model, lora_model, tokenizer = initialize_ml_models()