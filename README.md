You should Create this Python script threat_hunter.py at `/var/ossec/integrations`. This script does the following:
- Decompresses the logs from Wazuh archives for the specified period and loads them into a vector store. A vector store is a database that stores and retrieves vector embeddings (numerical representations of data such as text). Large language models (LLMs) use it to power features like semantic search and question answering.
- Starts Ollama and loads the Llama 3 LLM.
- Creates a webpage with a chatbot to query the logs.

Replace `<USERNAME>` and `<PASSWORD>` with your preferred username and password for accessing the LLM chatbot.
