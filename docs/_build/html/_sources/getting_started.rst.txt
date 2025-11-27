Getting Started
===============

This guide will walk you through the steps to get the Huntsman up and running using Docker Compose.

Prerequisites
-------------

* **Docker Engine** (version 20.10+)
* **Docker Compose** (version 2.0+)
* **Git**

Installation
------------

1. **Clone the Repository**

   .. code-block:: bash

      git clone https://github.com/aj-tap/huntsman
      cd huntsman

2. **Configure Environment**

   Huntsman requires API keys for services like VirusTotal and Shodan.

   .. tip::
      Start by copying the sample configuration file.

   .. code-block:: bash

      cp .env_sample .env

   Edit the ``.env`` file and add your specific API keys.

3. **Build and Run**

   Launch the entire stack (Django, Celery, Redis, SuperDB) in detached mode:

   .. code-block:: bash

      docker compose up --build -d

   * ``--build``: Forces a rebuild of the Docker images.
   * ``-d``: Runs containers in the background.

Verification
------------

Once the containers are running, verify the installation by checking the health endpoint:

.. code-block:: bash

   curl http://localhost:8000/api/health/

**Expected Output:**

.. code-block:: json

   {
     "database": {"status": "ok", "message": "Database connection successful."},
     "celery_redis": {"status": "ok", "message": "4 Celery worker(s) responded."}
   }

Stopping the Application
------------------------

To stop and remove the containers:

.. code-block:: bash

   docker compose down


Next Steps
----------

Now that the backend is running, explore the user interface.

* :doc:`usage`
* :doc:`rest_api`