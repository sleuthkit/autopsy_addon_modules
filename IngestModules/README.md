# Ingest Modules

Ingest modules analyze data sources in pipelines.  They can run in parallel and all files in the data source will typically be analyzed by them (unless there are ingest filters in place for triage situations). 

This is the most common extension point in Autopsy and modules can be written in either Java or Python.

These modules will analyze the content for differnet things and then post their results to the backend database so that they can be seen to the user. These modules do not have a user interface except for configuration. 

