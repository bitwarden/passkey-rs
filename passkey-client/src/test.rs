use passkey_authenticator::{Authenticator, MemoryStore, MockUserValidationMethod};
use passkey_types::{
    ctap2,
    webauthn::{
        AuthenticatorSelectionCriteria, ResidentKeyRequirement, UserVerificationRequirement,
    },
};

use crate::Client;

#[test]
fn map_rk_maps_criteria_to_rk_bool() {
    #[derive(Debug)]
    struct TestCase {
        resident_key: Option<ResidentKeyRequirement>,
        require_resident_key: bool,
        expected_rk: bool,
    }

    let test_cases = vec![
        // require_resident_key fallbacks
        TestCase {
            resident_key: None,
            require_resident_key: false,
            expected_rk: false,
        },
        TestCase {
            resident_key: None,
            require_resident_key: true,
            expected_rk: true,
        },
        // resident_key values
        TestCase {
            resident_key: Some(ResidentKeyRequirement::Discouraged),
            require_resident_key: false,
            expected_rk: false,
        },
        TestCase {
            resident_key: Some(ResidentKeyRequirement::Preferred),
            require_resident_key: false,
            expected_rk: true,
        },
        TestCase {
            resident_key: Some(ResidentKeyRequirement::Required),
            require_resident_key: false,
            expected_rk: true,
        },
        // resident_key overrides require_resident_key
        TestCase {
            resident_key: Some(ResidentKeyRequirement::Discouraged),
            require_resident_key: true,
            expected_rk: false,
        },
    ];

    for test_case in test_cases {
        let criteria = AuthenticatorSelectionCriteria {
            resident_key: test_case.resident_key,
            require_resident_key: test_case.require_resident_key,
            user_verification: UserVerificationRequirement::Discouraged,
            authenticator_attachment: None,
        };
        let auth_info = ctap2::get_info::Response {
            versions: vec![],
            extensions: None,
            aaguid: ctap2::Aaguid::new_empty(),
            options: Some(ctap2::get_info::Options {
                rk: true,
                uv: Some(true),
                up: true,
                plat: true,
                client_pin: None,
                ..Default::default()
            }),
            max_msg_size: None,
            pin_protocols: None,
            transports: None,
            ..Default::default()
        };
        let client = Client::new(Authenticator::new(
            ctap2::Aaguid::new_empty(),
            MemoryStore::new(),
            MockUserValidationMethod::verified_user(0),
        ));

        let result = client.map_rk(&Some(criteria), &auth_info);

        assert_eq!(result, test_case.expected_rk, "{test_case:?}");
    }
}
