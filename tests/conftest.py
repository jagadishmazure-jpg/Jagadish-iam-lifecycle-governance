import pytest

from iamlc.world import build


@pytest.fixture
def world():
    return build()


@pytest.fixture(scope="session")
def demo():
    from iamlc.scenario import run

    return {"full": run(naive=False), "naive": run(naive=True)}
