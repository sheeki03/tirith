#![no_main]
//! Fuzz target for the bounded GitHub Actions artifact-flow model.
//!
//! Arbitrary workflow text must never panic and must account deterministically.
//! A separately constructed valid JSON document (JSON is a YAML subset) proves
//! that one step beyond the caller's allowance reports the exact typed reason,
//! rather than merely touching the legacy truncation accessor.

use libfuzzer_sys::fuzz_target;
use std::path::Path;

use tirith_core::rules::workflow_artifacts::{self, WorkflowTruncationReason, MAX_TOTAL_STEPS};

const EXHAUSTION_BUDGET: usize = 8;

fuzz_target!(|data: &str| {
    let path = Path::new(".github/workflows/fuzz.yml");

    for budget in [MAX_TOTAL_STEPS, EXHAUSTION_BUDGET, 0] {
        let model = workflow_artifacts::build_model(path, data, budget);
        assert!(
            model.step_count() <= budget,
            "the model charged more steps than the caller's remaining budget"
        );
        assert_eq!(
            model.source_bytes(),
            data.len(),
            "the model's source-byte accounting changed"
        );

        let repeat = workflow_artifacts::build_model(path, data, budget);
        assert_eq!(
            model.step_count(),
            repeat.step_count(),
            "workflow modelling is not deterministic in step count"
        );
        assert_eq!(
            model.steps_truncated(),
            repeat.steps_truncated(),
            "workflow modelling is not deterministic in legacy truncation state"
        );
        assert_eq!(
            model.truncation_reasons().collect::<Vec<_>>(),
            repeat.truncation_reasons().collect::<Vec<_>>(),
            "workflow modelling is not deterministic in truncation reasons"
        );
    }

    // Exactly budget + 1 valid steps. The final step must be omitted for the
    // caller's step budget specifically; no other structural bound is near.
    let steps = (0..=EXHAUSTION_BUDGET)
        .map(|index| format!(r#"{{"name":"step-{index}","run":"echo fuzz"}}"#))
        .collect::<Vec<_>>()
        .join(",");
    let budget_probe = format!(r#"{{"jobs":{{"fuzz":{{"steps":[{steps}]}}}}}}"#);
    let model = workflow_artifacts::build_model(path, &budget_probe, EXHAUSTION_BUDGET);
    assert_eq!(model.step_count(), EXHAUSTION_BUDGET);
    assert!(model.steps_truncated());
    assert_eq!(
        model.truncation_reasons().collect::<Vec<_>>(),
        vec![WorkflowTruncationReason::StepBudgetExhausted]
    );
});
