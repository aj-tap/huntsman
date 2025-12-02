# Huntsman 

Huntsman is a Threat Intelligence and OSINT aggregator designed to streamline security operations.

It centralizes data from disparate sources, converts unstructured intelligence into structured STIX 2.1 objects, and visualizes relationships using an interactive graph engine. Huntsman aims to drastically reduce research time, allowing analysts to investigate threats faster and make informed decisions.


For further information on its functionality, refer to the article: 

[taming-the-threat-intelligence-beast-with-huntsman](https://shinkensec.com/2025/05/15/taming-the-threat-intelligence-beast-with-huntsman/)


## 🚀 Key Features

- Unified Intelligence: Aggregate data from over 20+ sources (VirusTotal, Shodan, OTX, etc.) into a single pane of glass.

- Zero-Code Integrations: Add new APIs or modify existing ones simply by editing a YAML configuration file.

- STIX 2.1 Native: Automatically normalizes unstructured data (IPs, Domains, Hashes) into standard STIX objects.

- Graph Visualization: visualize relationships between artifacts (pivoting) using an interactive link-node graph.

- Automated Pivoting: Define logic to automatically recursively search for related artifacts (e.g., "If you find a domain, automatically query for its A records").

- AI-Powered Analysis: Integrated with LiteLLM to support Gemini, GPT-4, and Ollama for summarization and correlation.


## 🛠️ Installation


### Prerequisites
- Docker (https://docs.docker.com/get-docker/)
- Docker Compose (Usually included with Docker Desktop, or see https://docs.docker.com/compose/install/)


## Setup & Running

### 1.  **Clone the Repository:**

```bash
git clone https://github.com/aj-tap/huntsman.git
cd huntsman
```    

### 2.  **Configure Environment Variables:**
Copy the sample environment file and add your API keys.

```bash
cp .env_sample .env
```

- **Edit the `.env` file:** Open the newly created `.env` file in a text editor.
- **Add API Keys:** Fill in the required API keys for the various threat intelligence services and analyzers you intend to use (e.g., VirusTotal, Shodan, etc.).
- **Set Django Secret Key:** Ensure the `DJANGO_SECRET_KEY` variable is set to a unique, strong, randomly generated key. You can generate one using Django's utility:
        
```bash
python manage.py shell -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'
```
- Review other variables in `.env` and adjust if necessary.

### 3.  **Build and Run with Docker Compose:**

- Launch the entire stack (Django, Celery, Redis, SuperDB). From the project's root directory (where `docker-compose.yml` and your `.env` file are located), run:
     
```bash
docker compose up --build -d
```
- Access the dashboard at: http://localhost:8000
- Default User: admin
- Default password: changeme

## ⚡ Easy Integration (YAML Configuration)

Huntsman uses declarative configuration engine. You don't need to write code to add a new API.

Open huntsman/config/api_recipes.yaml and add your endpoint:
```yaml
# Example: Adding a new service
myservice:
  enabled: true
  base_url: "https://api.myservice.com/v1"
  auth:
    type: "header"
    config:
      header_name: "X-API-KEY"
  endpoints:
    ipv4-addr:
      method: "GET"
      path_template: "/ip/{identifier}"
      llm_ioc_extract: false # If enable it will use LLM to extract iocs
      pivots:
        # Automatically extract domains from the response
        domain-name: "yield data.related_domains"
```


## 🤝 Contributing:
Contributions are welcome! Please read the contributing guidelines before submitting a pull request.
1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes.
4. Submit a pull request with a clear description of your changes.

## Show Your Support:
If you find Huntsman useful, consider supporting its development:
- Star the project on GitHub!
- Support the developer: https://buymeacoffee.com/ajtap
