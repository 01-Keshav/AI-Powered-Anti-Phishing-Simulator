import streamlit as st
import google.generativeai as genai
import re
import json

# Fallback Local Templates for Phishing Simulation (if Gemini is offline/unconfigured)
LOCAL_SIMULATION_TEMPLATES = {
    "IT": {
        "easy": {
            "subject": "⚠️ CRITICAL: Update your password immediately!",
            "body": "Dear User,\n\nOur system detected an unauthorized login attempt to your account from IP address 192.168.44.11. Due to security protocols, you must reset your password within the next 24 hours or your access will be permanently disabled.\n\nClick the link below to verify your identity and update your password:\nhttp://verify-login-update-portal.com/login\n\nBest Regards,\nIT Service Desk Support Team",
            "triggers": "Urgency, Fear",
            "mitre": "T1566.002 - Spearphishing Link",
            "indicators": ["Suspicious external domain (verify-login-update-portal.com)", "Generic salutation (Dear User)", "False sense of urgency (24 hours)", "Vague IT support signature"]
        },
        "medium": {
            "subject": "System Upgrade Notification - Action Required",
            "body": "Hello Employee,\n\nWe are migrating our enterprise identity portals to a new secure single sign-on (SSO) architecture this weekend. To ensure you do not lose access to your corporate email, Slack, and VPN, you are required to pre-register your credentials on the transition server.\n\nPlease complete the migration profile form here:\nhttps://sso-migration-portal.net/auth\n\nFailure to complete this migration by Friday 5:00 PM will require a physical trip to the IT depot for identity verification.\n\nSincerely,\nGlobal Identity & Access Management Team",
            "triggers": "Authority, Loss of Access",
            "mitre": "T1566.002 - Spearphishing Link",
            "indicators": ["External migration link", "Forced deadline before weekend", "Vague signature (Global IAM Team)", "Vague salutation"]
        },
        "hard": {
            "subject": "Scheduled IT Maintenance: MFA Configuration Audit",
            "body": "Hi [Name],\n\nAs part of our quarterly ISO 27001 compliance audit, the security operations team is reviewing Multi-Factor Authentication (MFA) enrollments. Our records indicate a mismatch in your hardware token registration.\n\nTo synchronize your mobile authenticator application, please visit the internal compliance dashboard page:\nhttps://compliance-auth-sso.com/mfa-sync\n\nIf you have any questions, you can contact the corporate security desk at extension x5443.\n\nRegards,\nSecurity Operations Analyst | ISO Compliance Branch",
            "triggers": "Trust, Duty, Authority",
            "mitre": "T1566.002 - Spearphishing Link",
            "indicators": ["Highly targeted domain name", "Appealing to corporate compliance policy", "Familiar language and extension mention", "Requires entering MFA synchronizations"]
        }
    },
    "HR": {
        "easy": {
            "subject": "🎉 Special Promotion: Free Amazon Gift Card!",
            "body": "Hi there,\n\nBecause of your hard work this quarter, the company is rewarding all active employees with a free $100 Amazon Gift Card! \n\nGet your claim code by clicking below and logging in with your corporate email address:\nhttp://employee-benefits-portal-gift.com/claim\n\nOffer expires tonight, so hurry!\n\nThanks,\nHuman Resources Benefits Department",
            "triggers": "Greed, Urgency",
            "mitre": "T1566.002 - Spearphishing Link",
            "indicators": ["External link requesting login", "Too good to be true offer", "Sense of urgency (expires tonight)", "Informal greeting"]
        },
        "medium": {
            "subject": "Updated Employee Dress Code and Conduct Policy",
            "body": "Dear Staff,\n\nPlease review the attached document outlining updates to the Employee Code of Conduct and Remote Work dress code policies, effective next month. \n\nAll employees are required to review the PDF policy document and digitally sign the acknowledgement page on the intranet server:\nhttps://hr-policy-portal.net/documents/dresscode.pdf.exe\n\nYour prompt attention to this matter is appreciated.\n\nRegards,\nCorporate HR & Payroll Operations",
            "triggers": "Authority, Conformity",
            "mitre": "T1566.001 - Spearphishing Attachment",
            "indicators": ["Double extension in link (.pdf.exe)", "HR Policy changes targeting staff", "Requires logging in to download or sign"]
        },
        "hard": {
            "subject": "Confidential Investigation: Salary Review Inquiry",
            "body": "Hi [Name],\n\nA discrepancy was flagged in your payroll tax declaration for Q2. As a result, the mid-year salary adjustments have been put on hold for your profile pending verification.\n\nPlease review the calculation spreadsheet attached to this email and reply with corrections by tomorrow morning.\n\nAttachments: salary_review_q2_confidential.xlsx.zip\n\nThank you,\nHR Compensation Committee",
            "triggers": "Fear, Curiosity",
            "mitre": "T1566.001 - Spearphishing Attachment",
            "indicators": ["Compressed zip file attachment", "High stakes (payroll and salary)", "Strict timeframe", "Confidential pretexting"]
        }
    }
}

# Rule-based Phishing Analyzer (Fallback if Gemini API key is missing)
def analyze_phishing_rules(email_text: str) -> dict:
    """Performs heuristic analysis on email content using regular expressions and keywords."""
    score = 10
    indicators = []
    
    # Common phishing keywords
    urgency_words = ["urgent", "immediately", "24 hours", "expires", "action required", "critical alert"]
    financial_words = ["bank", "wire transfer", "payroll", "invoice", "payment", "gift card", "reward", "compensate"]
    credential_words = ["password reset", "login portal", "verify identity", "confirm credentials", "sso lock"]
    
    # Analyze keywords
    urgency_matches = [w for w in urgency_words if re.search(r'\b' + re.escape(w) + r'\b', email_text.lower())]
    financial_matches = [w for w in financial_words if re.search(r'\b' + re.escape(w) + r'\b', email_text.lower())]
    credential_matches = [w for w in credential_words if re.search(r'\b' + re.escape(w) + r'\b', email_text.lower())]
    
    if urgency_matches:
        score += 20
        indicators.append(f"Urgency/Fear triggers detected: {', '.join(urgency_matches)}")
    if financial_matches:
        score += 15
        indicators.append(f"Financial transaction pretexts detected: {', '.join(financial_matches)}")
    if credential_matches:
        score += 25
        indicators.append(f"Credential harvesting keywords detected: {', '.join(credential_matches)}")
        
    # Link detection
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', email_text)
    if urls:
        score += 15
        indicators.append(f"Embedded links found in message body ({len(urls)} link(s))")
        for url in urls:
            # Check for suspicious external domains or IP addresses
            if any(term in url for term in ["verify", "login", "reset", "portal", "update", "signin"]) or re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
                score += 15
                indicators.append(f"Suspicious URL payload: '{url}' contains authentication-themed terms or IP addresses")
                break
                
    # Salutation analysis
    if re.search(r'(dear user|dear customer|hi there|attention employee)', email_text.lower()):
        score += 10
        indicators.append("Generic salutation matches common phishing templates")
        
    score = min(score, 100)
    
    # Rating assignment
    if score < 30:
        rating = "Safe"
        badge = "badge-green"
    elif score < 60:
        rating = "Low / Suspicious"
        badge = "badge-blue"
    elif score < 85:
        rating = "High Risk"
        badge = "badge-amber"
    else:
        rating = "Critical Phishing Threat"
        badge = "badge-red"
        
    return {
        "score": score,
        "rating": rating,
        "badge": badge,
        "indicators": indicators,
        "mitre": "T1566 - Phishing",
        "detailed_analysis": "Heuristic scanner evaluated email text for semantic alerts. High concentrations of urgency, financial incentives, and non-organizational links contributed to a heightened risk score."
    }

# AI-powered email analysis via Gemini
def analyze_phishing_ai(email_text: str, api_key: str) -> dict:
    """Uses Gemini API to perform deep threat intelligence analysis on a submitted email."""
    if not api_key:
        return analyze_phishing_rules(email_text)
        
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-2.5-flash")
        
        prompt = f"""
        Analyze the following email content for phishing indicators. 
        You are a Senior Threat Analyst evaluating potential initial access threats.
        Provide your assessment strictly in a JSON format matching the schema below.
        
        JSON SCHEMA:
        {{
          "score": integer (0 to 100 representing risk level),
          "rating": "Safe" | "Low" | "High Risk" | "Critical",
          "indicators": [string array of detected red flags],
          "mitre": "TXXXX.XXX MITRE ATT&CK technique name matching this email",
          "detailed_analysis": "Thorough analysis explaining psychological triggers, domain analysis, link risks, and indicators"
        }}
        
        EMAIL CONTENT:
        ---
        {email_text}
        ---
        
        Return ONLY the raw JSON block without markdown formatting or surrounding backticks.
        """
        
        response = model.generate_content(prompt)
        # Parse output safely
        text = response.text.strip()
        # Clean any markdown wrap if generated
        if text.startswith("```json"):
            text = text.split("```json", 1)[1].rsplit("```", 1)[0].strip()
        elif text.startswith("```"):
            text = text.split("```", 1)[1].rsplit("```", 1)[0].strip()
            
        data = json.loads(text)
        
        # Add badge class mapping
        rating = data.get("rating", "Low")
        if "Critical" in rating:
            data["badge"] = "badge-red"
        elif "High" in rating:
            data["badge"] = "badge-amber"
        elif "Safe" in rating:
            data["badge"] = "badge-green"
        else:
            data["badge"] = "badge-blue"
            
        return data
        
    except Exception as e:
        # Fallback to rules if AI call errors out
        res = analyze_phishing_rules(email_text)
        res["detailed_analysis"] += f"\n\n(AI Analysis failed due to: {str(e)}. Displaying Heuristic fallback.)"
        return res

# Generator for Phishing Simulations
def generate_phishing_template(department: str, difficulty: str, scenario: str, api_key: str = None) -> dict:
    """Generates a phishing simulation template using Gemini or local fallbacks."""
    if not api_key:
        # Grab local template
        dept_templates = LOCAL_SIMULATION_TEMPLATES.get(department, LOCAL_SIMULATION_TEMPLATES["IT"])
        return dept_templates.get(difficulty, dept_templates["easy"])
        
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("gemini-2.5-flash")
        
        prompt = f"""
        You are an Authorized Security Awareness Trainer. Generate a simulated phishing email for corporate education.
        Target Department: {department}
        Difficulty Level: {difficulty} (easy, medium, or hard. Easy should have obvious grammar or URL indicators. Hard should be sophisticated pretexting like CEO fraud or audit requests).
        Scenario: {scenario} (e.g. system lockout, HR policy, payroll inquiry, delivery notifications).
        
        Respond ONLY with a JSON object of this schema:
        {{
          "subject": "Subject of the email",
          "body": "Complete body of the email with placeholder links",
          "triggers": "psychological triggers used (comma separated list, e.g. Urgency, Greed, Trust)",
          "mitre": "TXXXX.XXX MITRE ATT&CK technique name associated",
          "indicators": [array of indicators and educational red flags that security analysts should spot]
        }}
        
        Make sure the email looks realistic for a corporate simulation but clearly contains indicators for training purposes.
        Return ONLY the raw JSON block without markdown formatting or surrounding backticks.
        """
        
        response = model.generate_content(prompt)
        text = response.text.strip()
        if text.startswith("```json"):
            text = text.split("```json", 1)[1].rsplit("```", 1)[0].strip()
        elif text.startswith("```"):
            text = text.split("```", 1)[1].rsplit("```", 1)[0].strip()
            
        return json.loads(text)
        
    except Exception:
        # Fallback to local template
        dept_templates = LOCAL_SIMULATION_TEMPLATES.get(department, LOCAL_SIMULATION_TEMPLATES["IT"])
        return dept_templates.get(difficulty, dept_templates["easy"])
