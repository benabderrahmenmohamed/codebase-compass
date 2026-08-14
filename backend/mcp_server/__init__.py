"""The MCP server: analysis tools Claude can call on demand.

Separate from the FastAPI app on purpose. FastAPI serves humans over HTTP;
this serves a model over the Model Context Protocol. They share the analysis
layer underneath and nothing else.
"""
