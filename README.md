# Huntsman 
================

Huntsman is a threat intel aggregator designed to streamline threat intelligence analysis for security operations. It aggregates data from various sources, provides multiple analysis views (Graph, Table, AI Insights, Detections), and offers a query language for custom detection rules. Huntsman aims to help analysts investigate threats faster, reduce research time, and make more informed decisions by centralizing and unifying threat intelligence data.

For further information on its functionality, refer to the article: 
[taming-the-threat-intelligence-beast-with-huntsman](https://shinkensec.com/2025/05/15/taming-the-threat-intelligence-beast-with-huntsman/)

## Prerequisites
-------------
- Docker (https://docs.docker.com/get-docker/)
- Docker Compose (Usually included with Docker Desktop, or see https://docs.docker.com/compose/install/)


## Setup & Running
---------------

1.  **Clone the Repository:**

```bash
git clone [https://github.com/aj-tap/huntsman](https://github.com/aj-tap/huntsman)
cd huntsman 
```    

2.  **Configure Environment Variables:**
    * This project requires API keys and other configuration settings to function correctly.
    * Copy the example environment file:

```bash
cp .env_sample .env
```

    * **Edit the `.env` file:** Open the newly created `.env` file in a text editor.
    * **Add API Keys:** Fill in the required API keys for the various threat intelligence services and analyzers you intend to use (e.g., VirusTotal, Shodan, MISP, etc.).
    * **Set Django Secret Key:** Ensure the `DJANGO_SECRET_KEY` variable is set to a unique, strong, randomly generated key. You can generate one using Django's utility:
        ```bash
        # Run this in your terminal within the project directory if you have a local Python env
        # OR generate it separately and paste it into the .env file.
        python manage.py shell -c 'from django.core.management.utils import get_random_secret_key; print(get_random_secret_key())'
        ```
    * Review other variables in `.env` and adjust if necessary.

3.  **Build and Run with Docker Compose:**
    * From the project's root directory (where `docker-compose.yml` and your `.env` file are located), run:
     
```bash
docker compose up --build -d
```

        * `--build`: Forces Docker to rebuild the images if the Dockerfile or related files have changed.
        * `-d`: Runs the containers in detached mode (in the background). Omit this if you want to see the logs directly in your terminal.

4.  **Access the Application:**
    * Once the containers are up and running, you should be able to access the Huntsman web interface in your browser at:
        http://127.0.0.1:8080 (or http://localhost:8080)

5. Default credentials are "admin" and "admin". Remember to change these in the admin dashboard.        

## Stopping the Application
------------------------

* To stop the running containers, navigate to the project's root directory in your terminal and run:
    
```bash
docker compose down
```

## Troubleshooting
---------------
If you encounter issues, check the Docker logs for error messages: docker-compose logs -f
- Ensure Docker and Docker Compose are installed and running correctly.
- Ensure all necessary ports (e.g., 8000) are not being used by other applications.
- Verify that all required API keys and the `DJANGO_SECRET_KEY` are correctly set in the `.env` file.
- Check the container logs for errors: `docker compose logs` or `docker compose logs -f <service_name>` (e.g., `docker compose logs -f web`).

## Contributing:
---------------
We welcome contributions to Huntsman! If you're interested in contributing, please:

1. Fork the repository.
2. Create a new branch for your feature or bug fix.
3. Make your changes.
4. Submit a pull request with a clear description of your changes.

## Show Your Support:
---------------
If you find Huntsman useful, consider supporting its development:

- Star the project on GitHub!
- Support the developer: https://buymeacoffee.com/ajtap
