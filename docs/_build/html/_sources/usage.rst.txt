Usage
===========================

The Huntsman Dashboard provides a visual interface for threat hunting, data exploration, and graph analysis. This guide covers the main functional areas of the application.

.. contents:: Table of Contents
   :local:
   :depth: 2

Dashboard Overview
------------------

Access the dashboard at ``http://localhost:8000/``.

The main layout consists of:

* **Top Navigation Bar**: Access to Settings, Documentation, and System Health.
* **Side Panel**: Quick access to recent Tasks, Saved Queries, and History.
* **Main Canvas**: The primary workspace for graph visualizations and query results.

Threat Detection
----------------

The Detection module allows you to submit artifacts (IOCs) to various analysis engines.

**Triggering an Analysis**

1. Locate the **Analysis Input** bar at the top of the dashboard.
2. Enter an artifact (e.g., ``google.com``, ``1.1.1.1``).
3. Select the target service from the dropdown (e.g., **VirusTotal**, **Shodan**).
4. Click **Analyze**.

.. note::
   The system automatically detects the identifier type (Domain, IP, Hash) based on regex patterns defined in ``ioc_patterns.yaml``.

**Viewing Results**

Once an analysis is complete, the results appear in the **Task Stream** on the right. Clicking a task will:

* Display the raw JSON result in the **Details Pane**.
* Render any extracted relationships (e.g., IP resolution, downloaded files) on the Graph.

SuperDB Explorer
----------------

SuperDB is the high-performance data lake backing Huntsman. The Explorer allows you to run **SuperQL** queries directly against your collected intelligence.

**Basic Query Structure**

SuperQL uses a pipe-based syntax similar to Splunk or Kusto.

.. code-block:: text

   from '<pool_name>' | <command> | <command>

**Common Examples**

* **Filter by IP:**

  .. code-block:: text

     from 'virustotal' | where id == '8.8.8.8'

* **Aggregate Data:**

  .. code-block:: text

     from 'shodan' | count() by asn

* **Text Search:**

  .. code-block:: text

     from 'rss-news' | search 'ransomware'

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