import streamlit as st
import google.generativeai as genai

# Setup system instruction for the SOC Analyst Assistant
SOC_SYSTEM_INSTRUCTION = (
    "You are Antigravity SOC Analyst Assistant, a Senior Level 2 Security Operations Center (SOC) Analyst and "
    "Threat Hunter. Your goal is to help blue teamers, incident responders, and security students analyze logs, "
    "interpret alerts, understand exploits, draft defensive rules (YARA, Sigma, Snort), and formulate containment strategies.\n\n"
    "When answering:\n"
    "1. Structure your answers logically with clear headings.\n"
    "2. Reference MITRE ATT&CK techniques (Txxxx) and the Cyber Kill Chain phases where relevant.\n"
    "3. Provide clean code snippets, commands, or rules inside markdown code blocks.\n"
    "4. Maintain a professional, technical, and highly analytical cybersecurity posture."
)

def render_soc_chatbot(api_key: str):
    """Renders the interactive Gemini SOC Analyst Chatbot."""
    st.markdown("""
    <div style="margin-bottom: 1rem;">
        <h3 style="margin: 0; font-size: 1.25rem;">Gemini SOC Security Assistant</h3>
        <p style="margin: 0; font-size: 0.8rem; color: var(--text-dim);">Ask threat hunting questions, analyze suspicious logs, or request detection rules.</p>
    </div>
    """, unsafe_allow_html=True)
    
    if not api_key:
        st.warning("⚠️ Gemini API key is missing. Please enter your API Key in the sidebar to activate the Security Assistant chatbot.")
        return
        
    # Initialize chat history in Streamlit session state
    if "soc_chat_history" not in st.session_state:
        st.session_state.soc_chat_history = [
            {"role": "assistant", "content": "Greetings Analyst. I am ready to assist. You can upload raw logs for analysis, ask about MITRE techniques, or request Yara/Sigma rules. What is your query?"}
        ]
        
    # Quick template buttons
    st.markdown("<span style='font-size: 0.75rem; font-weight:600; color: var(--text-muted);'>QUICK SEC SCENARIOS:</span>", unsafe_allow_html=True)
    q_col1, q_col2, q_col3 = st.columns(3)
    with q_col1:
        if st.button("📝 Explain Homoglyph Attacks", use_container_width=True):
            st.session_state.temp_prompt = "Explain homoglyph (typosquatting) initial access attacks and how to detect them using DNS logs."
    with q_col2:
        if st.button("🔍 Write Mimikatz Yara Rule", use_container_width=True):
            st.session_state.temp_prompt = "Write a simple YARA rule to detect Mimikatz strings (like sekurlsa, logonpasswords) in memory."
    with q_col3:
        if st.button("🪵 Analyze Web Log Line", use_container_width=True):
            st.session_state.temp_prompt = "Analyze this log line for attacks: 192.168.1.50 - - [03/Jul/2026:10:15:30 +0000] \"GET /index.php?file=../../../../etc/passwd HTTP/1.1\" 200 405"
            
    # Render existing conversation history
    # Streamlit standard container to wrap chat
    chat_container = st.container(height=380)
    with chat_container:
        for message in st.session_state.soc_chat_history:
            with st.chat_message(message["role"]):
                st.write(message["content"])
                
    # Get user prompt
    prompt = None
    if "temp_prompt" in st.session_state and st.session_state.temp_prompt:
        prompt = st.session_state.temp_prompt
        # Reset the temp state
        st.session_state.temp_prompt = None
    else:
        # st.chat_input waits for user entry
        prompt = st.chat_input("Ask a threat analysis question...")
        
    if prompt:
        # Add user question to history and show it
        st.session_state.soc_chat_history.append({"role": "user", "content": prompt})
        with chat_container:
            with st.chat_message("user"):
                st.write(prompt)
                
        # Generate model response
        with st.spinner("Analyzing threat profile..."):
            try:
                genai.configure(api_key=api_key)
                
                # Setup Chat with history
                model = genai.GenerativeModel(
                    model_name="gemini-2.5-flash",
                    system_instruction=SOC_SYSTEM_INSTRUCTION
                )
                
                # Format history for Gemini SDK
                # Gemini SDK expects a list of Contents: contents=[{'role':'user', 'parts': [...]}]
                gemini_contents = []
                # Include last 10 messages for context window efficiency
                for msg in st.session_state.soc_chat_history[-10:-1]: # exclude the latest user message which we will send
                    if msg["role"] == "assistant":
                        gemini_contents.append({"role": "model", "parts": [msg["content"]]})
                    else:
                        gemini_contents.append({"role": "user", "parts": [msg["content"]]})
                        
                chat = model.start_chat(history=gemini_contents)
                response = chat.send_message(prompt)
                
                response_text = response.text
                
                # Append assistant response to history
                st.session_state.soc_chat_history.append({"role": "assistant", "content": response_text})
                
                # Re-run to update container messages
                st.rerun()
                
            except Exception as e:
                st.error(f"Error communicating with Gemini API: {e}")
