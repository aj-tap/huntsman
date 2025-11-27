Configuration
=============

The Huntsman API is configured through a set of YAML files located in the ``huntsman/config`` directory. This guide acts as a complete reference for modifying these files to add new capabilities or services.

.. contents:: Table of Contents
   :local:
   :depth: 2

.. note::
   Changes to configuration files usually require a restart of the application or a call to the reload endpoint (if configured) to take effect.

API Recipes
-----------

**File:** ``api_recipes.yaml``

This is the core configuration file for Huntsman. It defines how the system connects to external APIs (like VirusTotal, Shodan, or your own internal tools). The structure is hierarchical: **Service** -> **Endpoint** -> **Identifier Type**.

Top-Level Keys
~~~~~~~~~~~~~~

For each service (e.g., ``virustotal``), the following keys are available:

.. list-table::
   :widths: 20 10 70
   :header-rows: 1

   * - Key
     - Required
     - Description
   * - ``enabled``
     - No
     - Boolean (``true``/``false``). Set to ``false`` to disable the entire service. Defaults to ``true``.
   * - ``base_url``
     - **Yes**
     - The root URL of the API (e.g., ``https://api.example.com/v1``).
   * - ``auth``
     - No
     - Authentication configuration object. See **Authentication** below.
   * - ``static_headers``
     - No
     - A dictionary of headers to send with *every* request (e.g., ``Accept: application/json``).
   * - ``endpoints``
     - **Yes**
     - A dictionary mapping **Identifier Types** to their specific API calls.

Authentication
~~~~~~~~~~~~~~

Huntsman supports flexible authentication injection. The ``auth`` block requires a ``type`` and a ``config`` object.

**Type: Header**
Injects the API key into a request header.

.. code-block:: yaml

   auth:
     type: "header"
     config:
       header_name: "X-API-KEY" # The header expected by the API

**Type: Param**
Injects the API key into the query string parameters.

.. code-block:: yaml

   auth:
     type: "param"
     config:
       param_name: "key" # The query param expected (e.g., ?key=XYZ)

Endpoint Configuration
~~~~~~~~~~~~~~~~~~~~~~

The ``endpoints`` block maps a specific **Identifier Type** (what you are analyzing) to an API action.

**Supported Identifier Types:**
``ipv4-addr``, ``ipv6-addr``, ``domain-name``, ``url``, ``file``, ``sha256``, ``md5``, ``sha1``, ``email-addr``, ``mac-addr``, ``vulnerability``, ``software``.

**Endpoint Keys:**

.. list-table::
   :widths: 20 10 70
   :header-rows: 1

   * - Key
     - Required
     - Description
   * - ``enabled``
     - No
     - Boolean (``true``/``false``). Set to ``false`` to disable this specific endpoint. Defaults to ``true``.
   * - ``method``
     - **Yes**
     - HTTP method: ``GET``, ``POST``, ``PUT``, etc.
   * - ``path_template``
     - **Yes**
     - The URL path. Supports variable injection (see below).
   * - ``params_template``
     - No
     - Query parameters. Supports simple strings or advanced objects (see **Advanced Parameters**).
   * - ``body_template``
     - No
     - A dictionary defining the request body structure. Supports variable injection.
   * - ``encoding``
     - No
     - Request body encoding: ``json`` (default) or ``form`` (application/x-www-form-urlencoded).
   * - ``db_pool``
     - **Yes**
     - The name of the SuperDB pool where results will be stored.
   * - ``ratelimit``
     - No
     - Format: ``<requests>/<period>`` (e.g., ``"1/5s"``, ``"100/d"``).
   * - ``pivots``
     - No
     - A mapping of relationships to extract. See **Pivots** below.

Advanced Parameters & Templating
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Values in ``path_template``, ``params_template``, and ``body_template`` support dynamic variable injection.

**Available Variables:**

* ``{identifier}``: The artifact being analyzed (e.g., "1.2.3.4").
* ``{today}``: The current date in ``YYYY-MM-DD`` format.
* ``{start_date}``: The date 30 days prior to today in ``YYYY-MM-DD`` format.

**Base64 Transformation:**

You can base64-encode parameter values (URL-safe) by using a dictionary with a ``transform`` key in ``params_template``.

.. code-block:: yaml

   params_template:
     raw_id: "{identifier}"
     # Example: Generates ?token=BASE64(2023-10-25:1.2.3.4)
     token:
       transform: "base64"
       template: "{today}:{identifier}"

**Request Body (JSON vs Form):**

For ``POST`` or ``PUT`` requests, you can define a body.

.. code-block:: yaml

   # JSON Example (Default)
   method: "POST"
   body_template:
     query: "{identifier}"
     from: "{start_date}"

   # Form Data Example
   method: "POST"
   encoding: "form"
   body_template:
     id: "{identifier}"
     format: "xml"

Pivots (Extraction Logic)
~~~~~~~~~~~~~~~~~~~~~~~~~

Pivots define how Huntsman "learns" from the data. They tell the system: *"When you get a result from this API, run this query to find related artifacts."*

**Format:** ``<Target Identifier Type>: "<SuperQL Query>"``

The SuperQL query operates on the JSON response from the API.

* **yield**: Returns a value.
* **cut**: Slices specific fields.
* **over**: Iterates over a list.

**Example:**

.. code-block:: yaml

   # API Response: {"data": {"attributes": {"last_dns_records": [{"type": "A", "value": "1.2.3.4"}]}}}
   
   pivots:
     # Extract 'A' records and treat them as new IPv4 addresses to investigate
     ipv4-addr: "over data.attributes.last_dns_records | type=='A' | yield value"

Full Recipe Example
~~~~~~~~~~~~~~~~~~~

.. code-block:: yaml

   virustotal:
     enabled: true
     base_url: "https://www.virustotal.com/api/v3"
     auth:
       type: "header"
       config:
         header_name: "x-apikey"
     endpoints:
       domain-name:
         enabled: true
         method: "GET"
         path_template: "/domains/{identifier}"
         db_pool: "virustotal"
         ratelimit: "1/5s"
         pivots:
           email-addr: "yield data.attributes.whois"
       
       # Example of advanced parameters and form encoding
       ipv4-addr:
         method: "POST"
         path_template: "/search"
         encoding: "form"
         params_template:
            # Base64 encode the identifier for a specific query param
            q:
              transform: "base64"
              template: "{identifier}"
         body_template:
            source: "huntsman"
            date: "{today}"
         db_pool: "virustotal"

Ratelimiting
------------

To prevent abuse and respect the terms of service of external APIs, you can add a ``ratelimit`` setting to any endpoint in ``api_recipes.yaml``.

**Format:** ``<calls>/<period>``

* ``<calls>``: Max requests allowed.
* ``<period>``: Time unit (``s`` = seconds, ``m`` = minutes, ``h`` = hours, ``d`` = days).

**Example:** ``ratelimit: "500/d"`` (500 calls per day).

Internal Services
-----------------

**File:** ``internal_services_recipe.yaml``

This file defines services that query your *local* SuperDB instance instead of an external API. This is useful for "Context" lookups (e.g., "Have we seen this IP in our RSS feeds?").

**Structure:**

.. code-block:: yaml

   rss-news:
     label: "RSS News Context"
     endpoints:
       ipv4-addr:
         # Standard SuperQL query. {identifier} is injected automatically.
         query_pattern: "from 'rss-news' | search '{identifier}' | head 1"
         pivots:
           all: "yield full_text"

IOC Patterns
------------

**File:** ``ioc_patterns.yaml``

This file contains Regex patterns used to automatically detect the type of an artifact (e.g., distinguishing an IP from a Domain).

.. code-block:: yaml

   ipv4-addr: \b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b
   email-addr: \b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b

Scraping Recipes
----------------

**File:** ``scraping_recipes.yaml``

Defines how to extract intelligence from raw HTML pages.

.. code-block:: yaml

   example_blog:
     base_url: https://example.com
     endpoints:
       post:
         path_template: /blog/{identifier}
         db_pool: example_blog_posts
         data_to_extract:
           # Key: XPath identifier
           title: "//h1/text()"
           content: "//div[@class='post-content']"

RSS Recipes
-----------

**File:** ``rss_recipes.yaml``

Configures RSS feeds for ingestion.

.. code-block:: yaml

   krebs_on_security:
     url: https://krebsonsecurity.com/feed/
     db_pool: krebs