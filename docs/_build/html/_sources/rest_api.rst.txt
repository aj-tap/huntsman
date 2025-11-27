REST API Reference
==================

The Huntsman REST API provides programmatic access to analysis tools, database operations, and intelligence workflows.

.. contents:: Table of Contents
   :local:
   :depth: 2

Overview
--------

* **Base URL**: ``http://<your-huntsman-host>:8000/api/``
* **Content-Type**: ``application/json``

Errors
------

The API uses standard HTTP status codes.

* ``200 OK``: Success.
* ``202 Accepted``: Task queued for background processing.
* ``400 Bad Request``: Invalid input (check your JSON syntax or missing fields).
* ``404 Not Found``: Resource not found.
* ``500 Internal Error``: Server-side failure.

Service Discovery
-----------------

**List Services**

``GET /services/``

Returns a list of all configured analysis services and the identifier types they support (e.g., ``domain-name``, ``ipv4-addr``).

**Response Example**

.. code-block:: json

   [
     {
       "name": "virustotal",
       "label": "Virustotal",
       "supported_types": ["domain-name", "ipv4-addr", "sha256", "file"]
     },
     {
       "name": "shodan",
       "label": "Shodan",
       "supported_types": ["ipv4-addr", "ipv6-addr", "domain-name", "jarm"]
     },
     {
       "name": "rss-news",
       "label": "RSS News Context",
       "supported_types": ["ipv4-addr", "domain-name", "vulnerability"]
     }
   ]

**Health Check**

``GET /health/``

Check the connectivity status of the Database and Celery workers.

Analysis Tasks
--------------

**Trigger Analysis**

``POST /analyze/``

Submit a single artifact for analysis by a specific service.

**Parameters**

* ``service_name`` (string, required): The service to use (must match a key in ``api_recipes.yaml`` or ``internal_services_recipe.yaml``).
* ``identifier`` (string, required): The artifact to analyze.
* ``identifier_type`` (string, required): The type of the artifact.

**Example 1: VirusTotal Domain Check**

.. code-block:: json

   {
     "service_name": "virustotal",
     "identifier": "google.com",
     "identifier_type": "domain-name"
   }

**Example 2: Shodan IP Scan**

.. code-block:: json

   {
     "service_name": "shodan",
     "identifier": "1.1.1.1",
     "identifier_type": "ipv4-addr"
   }

**Example 3: Internal RSS Search**

.. code-block:: json

   {
     "service_name": "rss-news",
     "identifier": "CVE-2023-1234",
     "identifier_type": "vulnerability"
   }

**Response (202 Accepted)**

.. code-block:: json

   {
     "message": "Analysis task has been queued.",
     "task_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6"
   }

**Bulk Analysis**

``POST /analyze/bulk/``

Submit multiple artifacts in a single batch.

**Parameters**

* ``tasks`` (array, required): List of task objects containing `service_name`, `identifier`, and `identifier_type`.

**Example Request**

.. code-block:: json

   {
     "tasks": [
       {
         "service_name": "virustotal",
         "identifier": "malware.exe",
         "identifier_type": "file"
       },
       {
         "service_name": "otx",
         "identifier": "192.168.1.5",
         "identifier_type": "ipv4-addr"
       }
     ]
   }

**Get Task Status**

``GET /tasks/<task_id>/``

Retrieve the status and full results of a task.

**Response Example**

.. code-block:: json

   {
     "id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
     "status": "SUCCESS",
     "service_name": "virustotal",
     "full_result": {
        "data": {
           "attributes": {
              "last_analysis_stats": {
                 "malicious": 0,
                 "suspicious": 0
              }
           }
        }
     }
   }

SuperDB Operations
------------------

**Execute Query**

``POST /query/``

Run a SuperQL query against the collected data.

**Parameters**

* ``query`` (string): Raw query string.
* ``from_pool`` (string): Pool name (if not using raw query).
* ``commands`` (array): List of commands (if not using raw query).

**Example 1: Aggregating Results (Predefined)**

This query attempts to normalize results across different services (VirusTotal and Shodan).

.. code-block:: json

   {
     "query": "switch (case grep('virustotal', this)=> {Results:'VTScore: ' + cast(data.attributes.last_analysis_stats, <string>), Link:'https://www.virustotal.com/gui/search/' + data.id} case grep('hostnames', this)=> {Results:'InternetDB: ' + cast(tags, <string>) + ' open ports' +cast(ports, <string>), Link:'https://internetdb.shodan.io/' + ip}) | Results!='null'"
   }

**Example 2: Simple Extraction**

Extract specific fields from a VirusTotal result.

.. code-block:: json

   {
     "query": "from 'virustotal' | yield data.attributes.last_analysis_results"
   }

**Example 3: Filtering IP Info**

Group IPInfo results by Organization/ASN.

.. code-block:: json

   {
     "query": "from 'ipinfo' | yield this | count() by this[\"org\"]"
   }

**Response**

.. code-block:: json

   {
     "message": "Database query task has been queued.",
     "task_id": "..."
   }

**Create Pool**

``POST /pool/create/``

Initialize a new data pool.

**Example Request**

.. code-block:: json

   {
     "name": "custom_threat_intel",
     "layout_keys": [["ts"], ["indicator_type"]]
   }

**Load Data**

``POST /branch/load-data/``

Inject raw data into a branch.

**Example Request**

.. code-block:: json

   {
     "pool_id_or_name": "custom_threat_intel",
     "branch_name": "main",
     "data": {
       "indicator": "1.2.3.4",
       "source": "manual_upload",
       "ts": 1716300000
     }
   }

Intelligence & Automation
-------------------------

**Run Correlation**

``POST /correlate/``

Apply rules to a completed task.

**Example Request**

.. code-block:: json

   {
     "task_id": "3fa85f64-5717-4562-b3fc-2c963f66afa6",
     "tags_filter": ["c2", "critical"]
   }

**AI Analysis**

``POST /ai/analyze/``

Send data to the AI engine for summarization.

**Example Request**

.. code-block:: json

   {
     "data": [{"log_entry": "Failed login attempt from 10.0.0.5"}],
     "prompt": "Analyze this log for security threats.",
     "system_prompt": "You are a senior SOC analyst."
   }