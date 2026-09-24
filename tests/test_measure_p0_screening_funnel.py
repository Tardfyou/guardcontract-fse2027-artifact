import sys

import pytest
from guardcontract.paths import project_root

sys.path.insert(0, str(project_root() / "tools"))
from measure_p0_screening_funnel import measure


def fixture():
    screening = {"full_772_screening_execution_complete": True, "input_drift": [], "rows": [
        {"unit": "a", "repository": "owner/app", "status": "applicable", "execution_health": "completed"},
        {"unit": "b", "repository": "owner/app", "status": "unresolved_contract", "execution_health": "completed"},
        {"unit": "c", "repository": "owner/other", "status": "not_applicable", "execution_health": "completed", "inherited_not_new_GLM_result": True}]}
    source = [{"sample_id": row["unit"], "repository": row["repository"], "framework": "framework", "source_family": "family"} for row in screening["rows"]]
    census = {"admitted_repositories": [{"repository": "another/population"}], "counts": {}}
    return screening, census, source


def test_frames_unknowns_and_inherited_protocols_remain_separate():
    value = measure(*fixture())
    assert value["population_join"]["repository_overlap"] == 0
    assert value["source_intake"]["units"] == 3
    assert value["source_intake"]["repositories"] == 2
    assert value["source_intake"]["source_families"] == 1
    assert value["source_intake"]["unit_statuses"]["unresolved_contract"] == 1
    assert len(value["source_intake"]["by_protocol_group"]) == 2
    assert not value["DEC_prevalence_available"]


def test_partial_execution_is_not_an_ecological_zero():
    screening, census, source = fixture()
    screening["full_772_screening_execution_complete"] = False
    with pytest.raises(ValueError, match="execution_not_complete"):
        measure(screening, census, source)


def test_source_family_and_exact_inventory_are_required():
    screening, census, source = fixture()
    source[0]["source_family"] = None
    with pytest.raises(ValueError, match="source_family_required"):
        measure(screening, census, source)
    screening, census, source = fixture()
    source.pop()
    with pytest.raises(ValueError, match="frame_inventory"):
        measure(screening, census, source)
