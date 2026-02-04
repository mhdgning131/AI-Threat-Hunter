You should Create this Python script threat_hunter.py at `/var/ossec/integrations`. This script does the following:
- Decompresses the logs from Wazuh archives for the specified period and loads them. 
- Starts Ollama and loads the phi3:mini LLM.
- Creates a webpage with a chatbot to query the logs.
