//! Private exact-commitment state for npm checkpoints. Only the enclosing
//! checkpoint extracts these values from typed core receipt capabilities.

pub(super) struct NpmReceiptBinding {
    operation_id: String,
    committed_receipt_id: Option<String>,
}

impl NpmReceiptBinding {
    pub(super) fn new(operation_id: String) -> Self {
        Self {
            operation_id,
            committed_receipt_id: None,
        }
    }

    pub(super) fn bind_prepared(
        &mut self,
        operation_id: Option<&str>,
        committed_receipt_id: &str,
    ) -> std::io::Result<()> {
        if operation_id != Some(self.operation_id.as_str())
            || committed_receipt_id.len() != 64
            || !committed_receipt_id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || self
                .committed_receipt_id
                .as_deref()
                .is_some_and(|id| id != committed_receipt_id)
        {
            return Err(refusal("prepared receipt does not bind this npm operation"));
        }
        self.committed_receipt_id = Some(committed_receipt_id.into());
        Ok(())
    }

    pub(super) fn require_prepared(&self) -> std::io::Result<()> {
        if self.committed_receipt_id.is_none() {
            return Err(refusal(
                "npm publication requires its exact prepared committed receipt",
            ));
        }
        Ok(())
    }

    pub(super) fn verify_committed(&self, receipt_id: &str) -> std::io::Result<()> {
        if self.committed_receipt_id.as_deref() != Some(receipt_id) {
            return Err(refusal(
                "committed receipt does not match this npm checkpoint",
            ));
        }
        Ok(())
    }
}

fn refusal(message: &'static str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unbound_or_other_operation_receipt_never_enables_publication() {
        let mut binding = NpmReceiptBinding::new("operation-a".into());
        let id = "a".repeat(64);
        assert!(binding.require_prepared().is_err());
        assert!(binding.verify_committed(&id).is_err());
        for operation in [None, Some("operation-b")] {
            assert!(binding.bind_prepared(operation, &id).is_err());
            assert!(binding.require_prepared().is_err());
        }
        for invalid_id in ["", "UPPERCASE", "a/../b"] {
            assert!(binding
                .bind_prepared(Some("operation-a"), invalid_id)
                .is_err());
        }
        assert!(binding.require_prepared().is_err());
    }

    #[test]
    fn exact_preparation_is_idempotent_and_cannot_be_swapped_before_commit() {
        let mut binding = NpmReceiptBinding::new("operation-a".into());
        let first = "a".repeat(64);
        let other = "b".repeat(64);
        binding.bind_prepared(Some("operation-a"), &first).unwrap();
        binding.require_prepared().unwrap();
        binding.bind_prepared(Some("operation-a"), &first).unwrap();
        assert!(binding.bind_prepared(Some("operation-a"), &other).is_err());
        assert!(binding.bind_prepared(Some("operation-b"), &first).is_err());
        assert!(binding.verify_committed(&other).is_err());
        binding.verify_committed(&first).unwrap();
    }
}
