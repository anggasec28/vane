from vane.validation.readiness import evaluate_release_readiness

def test_runtime_and_production_are_separate_gates():
    report = evaluate_release_readiness(tests_passed=True, manifest_verified=True,
        decision_traceability_complete=True)
    assert not report.ready
    assert not next(i for i in report.items if i.name == "runtime_approval").passed
