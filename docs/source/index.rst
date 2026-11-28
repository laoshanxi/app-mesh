.. app-mesh documentation master file, created by
   sphinx-quickstart on Wed Feb  3 17:17:10 2021.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to App Mesh's documentation!
====================================

.. toctree::
   :maxdepth: 2
   :caption: Overview:
   :numbered:

   README.md
   FeatureOverview.md


.. toctree::
   :maxdepth: 2
   :caption: Engine:
   :numbered:

   engine/AppManagement.md
   engine/TaskRun.md
   engine/Docker.md
   engine/Files.md
   engine/Cluster.md
   engine/LLM.md
   engine/RemoteSandbox.md
   engine/workflow/Workflow.md
   engine/workflow/WorkflowSchema.md


.. toctree::
   :maxdepth: 2
   :caption: Interfaces:
   :numbered:

   interfaces/CLI.md
   interfaces/RESTAPI.md
   interfaces/SDKContract.md
   interfaces/EventSubscription.md
   interfaces/Streaming.md
   interfaces/api/appmesh


.. toctree::
   :maxdepth: 2
   :caption: Security:
   :numbered:

   security/Security.md
   security/Authentication.md
   security/TLS.md
   security/OSUser.md


.. toctree::
   :maxdepth: 2
   :caption: Cloud Native:
   :numbered:

   observability/Prometheus.md
   observability/Grafana.md
   observability/Loki.md
   observability/Kubernetes.md


.. toctree::
   :maxdepth: 2
   :caption: Deployment:
   :numbered:

   deploy/Install.md
   deploy/Ports.md
   deploy/WorkDir.md


.. toctree::
   :maxdepth: 2
   :caption: Development:
   :numbered:

   development/Build.md
   development/Release.md
   development/Coverity.md
   development/MemoryTool.md


.. toctree::
   :maxdepth: 2
   :caption: Technical Notes:
   :numbered:

   technical/Protocols.md
   technical/Conventions.md


.. toctree::
   :maxdepth: 1
   :caption: Success Stories:
   :numbered:

   success/remote_run_cli_and_python.md
   success/build_powerful_monitor_system_with_Grafana_Prometheus_Loki.md
   success/customize_app_startup_behavior.md
   success/promote_native_app_to_microservice_app.md
   success/secure_REST_file_server.md
   success/python_parallel_run.md
