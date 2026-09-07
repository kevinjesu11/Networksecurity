"""Guards against blocking work being reintroduced onto the event loop.

The prediction and training handlers do blocking work: DNS, an HTTP fetch, a
WHOIS lookup, pandas, and in /train an entire training run. Declared
`async def`, that work runs on the event loop and stalls every other request --
one slow scan pushed /health from 0.01s to 4.6s, past the 5s timeout on the
container healthcheck in the Dockerfile. Declared `def`, FastAPI runs them in
its threadpool instead.

The distinction is invisible at a glance and easy to undo, so it is asserted
here rather than left to review.
"""

import inspect

import app as app_module

BLOCKING_HANDLERS = ["train_route", "predict_route", "predict_url_route"]


def _handler(name):
    return getattr(app_module, name)


def test_blocking_handlers_are_not_coroutines():
    """Each must be a plain function so FastAPI offloads it to a thread."""
    for name in BLOCKING_HANDLERS:
        handler = _handler(name)
        assert not inspect.iscoroutinefunction(handler), (
            f"{name} is `async def`, so its blocking I/O runs on the event loop "
            f"and stalls every other request. Declare it `def`."
        )


def test_index_and_health_stay_async():
    """These do no blocking work; running them on the loop is correct and keeps
    the healthcheck responsive."""
    for name in ["index", "health"]:
        assert inspect.iscoroutinefunction(_handler(name))


def test_upload_is_read_synchronously():
    """A sync handler cannot await, so the upload must be read off the spooled
    file directly -- an `await file.read(...)` here would raise at runtime."""
    source = inspect.getsource(_handler("predict_route"))
    assert "await " not in source, (
        "predict_route is a sync handler; `await` in its body will fail at runtime"
    )
    assert "file.file.read" in source
