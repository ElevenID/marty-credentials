//! Credentials keeps the compressed-only status-list Python API.

pub use marty_python_adapters::status_list::compressed::register as register_status_list_module;

#[cfg(test)]
mod tests {
    use marty_python_adapters::status_list::compressed::*;

    #[test]
    fn selected_profile_keeps_credentials_exports_and_defaults() {
        use pyo3::prelude::*;
        Python::initialize();
        Python::attach(|py| {
            let module = PyModule::new(py, "_marty_rs").unwrap();
            super::register_status_list_module(&module).unwrap();
            for name in ["TokenStatusList", "BitstringStatusList"] {
                let class = module.getattr(name).unwrap();
                assert!(!class.hasattr("from_bytes").unwrap());
                assert!(class.is(module
                    .getattr("status_list")
                    .unwrap()
                    .getattr(name)
                    .unwrap()));
            }
            let list = module
                .getattr("TokenStatusList")
                .unwrap()
                .call1((2,))
                .unwrap();
            assert_eq!(
                list.call_method0("bits_per_status")
                    .unwrap()
                    .extract::<u8>()
                    .unwrap(),
                8
            );
        });
    }

    #[test]
    fn binding_preserves_ietf_normative_vector() {
        let values = [1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0, 1];
        let mut list = TokenStatusList::new(values.len(), 1).unwrap();
        for (index, value) in values.into_iter().enumerate() {
            list.set(index, value).unwrap();
        }
        assert_eq!(list.to_bytes(), vec![0xb9, 0xa3]);
        assert_eq!(list.to_base64url().unwrap(), "eNrbuRgAAhcBXQ");
    }

    #[test]
    fn binding_preserves_multibit_roundtrip() {
        let mut list = TokenStatusList::new(100, 2).unwrap();
        for (index, value) in [0, 1, 2, 3].into_iter().enumerate() {
            list.set(index, value).unwrap();
        }
        let restored =
            TokenStatusList::from_base64url(&list.to_base64url().unwrap(), 100, 2).unwrap();
        assert_eq!(restored.to_bytes()[0], 0b1110_0100);
    }

    #[test]
    fn binding_preserves_w3c_multibase_contract() {
        let mut list = BitstringStatusList::new(marty_status::W3C_MIN_STATUS_LIST_BITS).unwrap();
        list.revoke(0).unwrap();
        list.revoke(7).unwrap();
        assert_eq!(list.to_bytes()[0], 0b1000_0001);
        let encoded = list.to_base64url().unwrap();
        assert!(encoded.starts_with('u'));
        let restored = BitstringStatusList::from_base64url(&encoded, list.len()).unwrap();
        assert_eq!(restored.count_revoked(), 2);
    }

    #[test]
    fn binding_rejects_malformed_and_unreasonable_inputs() {
        assert!(TokenStatusList::from_compressed(vec![1, 2, 3], 100, 8).is_err());
        assert!(BitstringStatusList::from_base64url("not-multibase", 8).is_err());
        assert!(TokenStatusList::new(marty_status::MAX_STATUS_LIST_ENTRIES + 1, 8).is_err());
    }

    #[test]
    fn binding_subject_uses_canonical_privacy_floor() {
        let small = BitstringStatusList::new(marty_status::W3C_MIN_STATUS_LIST_BITS - 1).unwrap();
        assert!(
            create_bitstring_credential_subject(&small, "urn:example:list", "revocation").is_err()
        );
    }
}
