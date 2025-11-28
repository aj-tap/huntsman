Usage
===========================

The Huntsman Dashboard provides a visual interface for threat hunting, data exploration, and graph analysis. This guide covers the main functional areas of the application.

.. contents:: Table of Contents
   :local:
   :depth: 2

Dashboard Overview
------------------

Access the dashboard at ``http://localhost:8080/``.

The interface is designed as a Single Page Application (SPA) with three primary views:

* **Input View**: For ingesting raw text or manually staging artifacts.
* **Monitor View**: For tracking the status of running analysis tasks.
* **Results View**: For exploring the Intelligence Graph, detection lists, and data lake.

Threat Detection
----------------

Threat Detection
----------------

The Detection module allows you to submit artifacts (IOCs) to various analysis engines using two modes.

**1. Auto-Ingestion (Regex)**

1. Navigate to the **Auto** tab in the Input View.
2. Paste unstructured logs, CSVs, or text into the **Raw Data Ingestion** text area.
3. The system automatically detects and counts artifacts (e.g., IPv4, Domains) using patterns defined in ``ioc_patterns.yaml``.

**2. Manual Input**

1. Navigate to the **Manual Input** tab.
2. Select an **Indicator Type** from the dropdown.
3. Enter the **Indicator Value** and click **Add** to stage the artifact.

**Executing Analysis**

1. In the **Enrichment Modules** section, filter and select the desired services (e.g., *VirusTotal*, *Shodan*) using the checkboxes.
2. Click **Execute Analysis**.
3. The view will automatically switch to the **Monitor View** to show task progress.

SuperDB Explorer
----------------

SuperDB is the high-performance data lake backing Huntsman. The Explorer interface allows you to run SuperQL queries directly against your collected intelligence. By leveraging a compiled WebAssembly (WASM) version of the SuperDB engine, the frontend performs serverless, client-side ETL operations on loaded data without needing to query the server. For direct queries against the full persistent data lake, please refer to the REST API.

**Basic Query Structure**

SuperQL uses a pipe-based syntax similar to Splunk or Kusto.

.. code-block:: text

   _service = '<value>' | <command> | <command>

**Common Examples**

* **Filter by IP:**

  .. code-block:: text

     _service = 'virustotal' | where id == '8.8.8.8'

* **Aggregate Data:**

  .. code-block:: text

     _service = 'internetdb' | count() by hostnames

* **Text Search:**

  .. code-block:: text

     _service = 'rss-news' | search 'ransomware'


**Visualizing Query Results**

Results from SuperDB can be dragged and dropped onto the Graph Canvas to visualize connections between disparate data points.

STIX Visualization
------------------

Huntsman natively supports STIX 2.1 (Structured Threat Information Expression) for representing threat intelligence.

**Graph Canvas**

The central area of the application is a force-directed graph that visualizes STIX objects.

* **Nodes**: Represent SDOs (Domain Objects) like *Indicators*, *Malware*, or *Threat Actors*.
* **Edges**: Represent SROs (Relationship Objects) like *indicates*, *uses*, or *attributed-to*.

**Generating Reports**

You can convert any analysis task into a standardized STIX report:

1. Select a completed task from the **History**.
2. Click the **"Generate STIX"** button in the context menu.
3. The system will map the raw API data (e.g., from VirusTotal) into valid STIX objects (e.g., ``ipv4-addr``, ``domain-name``).

**Icons & Styling**

The graph uses standard STIX 2.1 icons to help you quickly identify object types:

* |icon_malware| **Malware**: Red/Square icons.
* |icon_identity| **Identity**: Grey/Round icons.
* |icon_indicator| **Indicator**: Orange/Diamond icons.

.. |icon_malware| image:: images/icons/stix2-ttp-icons-png/malware-square-flat-300-dpi.png
   :width: 20px
   :alt: Malware Icon

.. |icon_identity| image:: images/icons/stix2-meta-icons-png/identity-round-flat-300-dpi.png
   :width: 20px
   :alt: Identity Icon

.. |icon_indicator| image:: images/icons/stix2-ir-icons-png/indicator-square-flat-300-dpi.png
   :width: 20px
   :alt: Indicator Icon