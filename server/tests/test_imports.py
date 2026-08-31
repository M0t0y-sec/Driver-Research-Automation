"""smoke test: import the whole package."""
def test_imports():
    import dra
    from dra import models, storage, llm, tools, agents, evidence, qa, compliance, untrusted, graph
    from dra.api import health, projects, targets, research, reads, lab, dashboard
    from dra.main import app
    assert app.title.startswith("DRA")
