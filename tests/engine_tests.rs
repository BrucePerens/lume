use lume::{storage::MailHeader, LumeEngine, LumeError};
use std::sync::Arc;

// [@ANCHOR: integration_engine_test]
#[tokio::test]
async fn test_full_email_lifecycle() {
    let test_dir = std::env::temp_dir().join(format!("lume_test_env_{}", uuid::Uuid::new_v4()));
    let _ = std::fs::remove_dir_all(&test_dir);

    let engine = LumeEngine::new(test_dir.clone()).expect("Failed to initialize LumeEngine");
    LumeEngine::init_db(&engine.db).expect("Failed to initialize SQLite database");

    let plain_password = "super_secure_test_password";
    let acl_id = engine
        .register_user("test_user", plain_password)
        .expect("Failed to register user");

    let auth_acl_id = engine
        .authenticate_user("test_user", plain_password)
        .expect("Failed to authenticate");
    assert_eq!(
        acl_id, auth_acl_id,
        "Authenticated ACL ID does not match registered ACL ID"
    );

    let message_id = "test_msg_001";
    let raw_email = b"From: alice@example.com\r\nTo: bob@example.com\r\nSubject: Secret Project\r\n\r\nThis is the highly compressible text body of the email.";

    let stored_path = engine
        .store_email(message_id, acl_id, raw_email)
        .await
        .expect("Failed to store email");
    assert!(
        stored_path.exists(),
        "Stored email file does not exist on disk"
    );

    let header = MailHeader {
        dict_id: engine.compression_manager.get_active_dict_id(),
        acl_id,
        original_checksum: 0,
        text_len: 0,
    };
    engine
        .index_message(message_id, &header, "Secret Project", "alice@example.com")
        .expect("Failed to index message");

    let authorized_dict = engine
        .authorize_and_get_dict(message_id, auth_acl_id)
        .expect("Failed to authorize email access");
    assert_eq!(
        authorized_dict,
        engine.compression_manager.get_active_dict_id()
    );

    let retrieved_email = engine
        .get_email(message_id)
        .await
        .expect("Failed to retrieve email");
    assert_eq!(
        raw_email.to_vec(),
        retrieved_email,
        "Retrieved email content does not match original"
    );

    let _ = std::fs::remove_dir_all(&test_dir);
}

#[tokio::test]
async fn test_authentication_failures_and_timing_mitigation() {
    let test_dir = std::env::temp_dir().join(format!("lume_test_auth_{}", uuid::Uuid::new_v4()));
    let _ = std::fs::remove_dir_all(&test_dir);

    let engine = LumeEngine::new(test_dir.clone()).expect("Failed init");
    LumeEngine::init_db(&engine.db).expect("Failed init DB");

    engine
        .register_user("real_user", "correct_password")
        .unwrap();

    // 1. Wrong Password (Exercises Argon2 failure path)
    let bad_pass = engine.authenticate_user("real_user", "wrong_password");
    assert!(matches!(bad_pass, Err(LumeError::AccessDenied)));

    // 2. Non-existent User (Exercises dummy hash timing mitigation path)
    let no_user = engine.authenticate_user("ghost_user", "password123");
    assert!(matches!(no_user, Err(LumeError::AccessDenied)));

    let _ = std::fs::remove_dir_all(&test_dir);
}

#[tokio::test]
async fn test_acl_isolation() {
    let test_dir = std::env::temp_dir().join(format!("lume_test_acl_{}", uuid::Uuid::new_v4()));
    let _ = std::fs::remove_dir_all(&test_dir);

    let engine = LumeEngine::new(test_dir.clone()).expect("Failed init");
    LumeEngine::init_db(&engine.db).expect("Failed init DB");

    let user_a_id = engine.register_user("user_a", "pass_a").unwrap();
    let user_b_id = engine.register_user("user_b", "pass_b").unwrap();

    let message_id = "confidential_msg";
    let raw_email = b"Top Secret Data for User A";

    engine
        .store_email(message_id, user_a_id, raw_email)
        .await
        .unwrap();
    let header = MailHeader {
        dict_id: 0,
        acl_id: user_a_id,
        original_checksum: 0,
        text_len: 0,
    };
    engine
        .index_message(message_id, &header, "Subject", "Sender")
        .unwrap();

    // User A can access
    assert!(engine.authorize_and_get_dict(message_id, user_a_id).is_ok());

    // User B CANNOT access
    let unauthorized_access = engine.authorize_and_get_dict(message_id, user_b_id);
    assert!(matches!(unauthorized_access, Err(LumeError::AccessDenied)));

    let _ = std::fs::remove_dir_all(&test_dir);
}

#[tokio::test]
async fn test_concurrent_storage_and_wal() {
    let test_dir =
        std::env::temp_dir().join(format!("lume_test_concurrent_{}", uuid::Uuid::new_v4()));
    let _ = std::fs::remove_dir_all(&test_dir);

    let engine = Arc::new(LumeEngine::new(test_dir.clone()).expect("Failed init"));
    LumeEngine::init_db(&engine.db).expect("Failed init DB");

    let acl_id = engine.register_user("stress_user", "pass").unwrap();

    let mut handles = vec![];

    // Spawn 50 concurrent tasks attempting to write and index emails simultaneously.
    // This tests the UUID tmp file generation preventing file locks, and the WAL journal
    // mode preventing SQLite database locks.
    for i in 0..50 {
        let engine_clone = Arc::clone(&engine);
        let handle = tokio::spawn(async move {
            let msg_id = format!("msg_{}", i);
            let payload = format!("Concurrent payload {}", i);

            engine_clone
                .store_email(&msg_id, acl_id, payload.as_bytes())
                .await
                .unwrap();

            let header = MailHeader {
                dict_id: 0,
                acl_id,
                original_checksum: 0,
                text_len: 0,
            };
            engine_clone
                .index_message(&msg_id, &header, "Subject", "Sender")
                .unwrap();
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.await.unwrap();
    }

    // Verify all 50 made it to disk and index
    let db = engine.db.lock().unwrap();
    let mut stmt = db.prepare("SELECT count(*) FROM messages").unwrap();
    let count: i64 = stmt.query_row([], |row| row.get(0)).unwrap();
    assert_eq!(count, 50);
    drop(stmt);
    drop(db);

    let _ = std::fs::remove_dir_all(&test_dir);
}

#[tokio::test]
async fn test_corruption_detection_magic_bytes() {
    let test_dir = std::env::temp_dir().join(format!("lume_test_magic_{}", uuid::Uuid::new_v4()));
    let _ = std::fs::remove_dir_all(&test_dir);
    let engine = LumeEngine::new(test_dir.clone()).unwrap();
    LumeEngine::init_db(&engine.db).unwrap();
    let acl_id = engine.register_user("user", "pass").unwrap();

    let msg_id = "msg_magic";
    let path = engine
        .store_email(msg_id, acl_id, b"payload")
        .await
        .unwrap();

    // Overwrite the first 4 bytes (LMAI magic)
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    file.write_all(b"BAD!").unwrap();
    file.sync_all().unwrap();

    let res = engine.get_email(msg_id).await;
    assert!(matches!(res, Err(LumeError::Corruption)));

    let _ = std::fs::remove_dir_all(&test_dir);
}

#[tokio::test]
async fn test_corruption_detection_payload_checksum() {
    let test_dir = std::env::temp_dir().join(format!("lume_test_chk_{}", uuid::Uuid::new_v4()));
    let _ = std::fs::remove_dir_all(&test_dir);
    let engine = LumeEngine::new(test_dir.clone()).unwrap();
    LumeEngine::init_db(&engine.db).unwrap();
    let acl_id = engine.register_user("user", "pass").unwrap();

    let msg_id = "msg_chk";
    let path = engine
        .store_email(msg_id, acl_id, b"sensitive data payload")
        .await
        .unwrap();

    // Append a single byte to the end of the file to corrupt the checksum
    use std::io::Write;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .append(true)
        .open(&path)
        .unwrap();
    file.write_all(b"x").unwrap();
    file.sync_all().unwrap();

    let res = engine.get_email(msg_id).await;
    assert!(matches!(res, Err(LumeError::Corruption)));

    let _ = std::fs::remove_dir_all(&test_dir);
}

#[tokio::test]
async fn test_empty_payload_storage() {
    let test_dir = std::env::temp_dir().join(format!("lume_test_empty_{}", uuid::Uuid::new_v4()));
    let _ = std::fs::remove_dir_all(&test_dir);
    let engine = LumeEngine::new(test_dir.clone()).unwrap();
    LumeEngine::init_db(&engine.db).unwrap();
    let acl_id = engine.register_user("user", "pass").unwrap();

    let msg_id = "msg_empty";
    engine.store_email(msg_id, acl_id, b"").await.unwrap();

    let retrieved = engine.get_email(msg_id).await.unwrap();
    assert_eq!(retrieved.len(), 0);

    let _ = std::fs::remove_dir_all(&test_dir);
}

#[test]
fn test_security_primitives() {
    let pass = "complex_passphrase_123";
    let hash = lume::security::hash_password(pass).unwrap();
    assert!(lume::security::verify_password(pass, &hash).unwrap());
    assert!(!lume::security::verify_password("wrong", &hash).unwrap());
}

#[tokio::test]
async fn test_compression_efficiency_tracker() {
    let manager = lume::compression::CompressionManager::new();
    for _ in 0..100 {
        let data = b"repeated data repeated data repeated data repeated data";
        let _ = manager.compress(data).unwrap();
    }
}

const ENRON_EMAIL_1: &str = r#"Message-ID: <13505866.1075863688222.JavaMail.evans@thyme>
Date: Wed, 31 Oct 2001 07:02:27 -0800 (PST)
From: pr.palmer@enron.com
To: richard.shapiro@enron.com, j..kean@enron.com, linda.robertson@enron.com
Subject: FW: Here from scratch what's your fax # we can try the old fashioned way!

I've answered all their questions, and have suggested to Chris that he ask NorthWestern for audited financials. Marissa is preparing a letter which briefly outlines the deal, since GE had requested a letter identifying the parties, the payment obligations, etc. I've given them all this information previously in phone calls and by email, but I think they want something official looking. Probably be a good idea for you to sign the letter. I don't think they will trade payment for a consent, but I could be wrong. It just isn't enough money, and GE isn't strapped for cash anyway. I'd want to be careful that we don't trip up on E - Next obligations.

Kay

I'd like to hold payment on this invoice until we receive the consent from GE. Any update?
"#;

const ENRON_EMAIL_2: &str = r#"Message-ID: <33076797.1075855687515.JavaMail.evans@thyme>
Date: Mon, 16 Oct 2000 13:42:00 -0700 (PDT)
From: phillip.allen@enron.com
To: buck.buckner@honeywell.com
Subject: Re: FW: fixed forward or other Collar floor gas price terms

Mr. Buckner,

For delivered gas behind San Diego, Enron Energy Services is the appropriate Enron entity. I have forwarded your request to Zarin Imam at EES. Her phone number is 713-853-7107.

Phillip Allen
"#;

// [@ANCHOR: massive_email_lifecycle_test]
#[tokio::test]
async fn test_massive_email_lifecycle_and_regeneration() {
    let test_dir = std::env::temp_dir().join(format!("lume_test_massive_{}", uuid::Uuid::new_v4()));
    let _ = std::fs::remove_dir_all(&test_dir);

    let engine = LumeEngine::new(test_dir.clone()).expect("Failed to init LumeEngine");
    LumeEngine::init_db(&engine.db).expect("Failed to init DB");

    let owner_acl = engine.register_user("alpha_user", "secure_pass").unwrap();
    let attacker_acl = engine
        .register_user("beta_attacker", "hacker_pass")
        .unwrap();

    assert_eq!(engine.compression_manager.get_active_dict_id(), 0);

    // 1. Store thousands of emails to simulate a realistic bulk import and trigger dictionary generation.
    // We use actual Enron corpus text. However, to ensure the Zstandard compression ratio
    // crosses the 0.75 threshold required for a dictionary rebuild, we append
    // high-entropy data (simulating encrypted attachments or compressed archives) to a subset of emails.
    for i in 0..5_000 {
        let msg_id = format!("mass_msg_{}", i);
        let mut raw_email = if i % 2 == 0 {
            ENRON_EMAIL_1.as_bytes().to_vec()
        } else {
            ENRON_EMAIL_2.as_bytes().to_vec()
        };

        // Append raw entropy to force ratio > 0.75 across the rolling window
        for _ in 0..50 {
            raw_email.extend_from_slice(uuid::Uuid::new_v4().as_bytes());
        }

        engine
            .store_email(&msg_id, owner_acl, &raw_email)
            .await
            .unwrap();

        let header = MailHeader {
            dict_id: engine.compression_manager.get_active_dict_id(),
            acl_id: owner_acl,
            original_checksum: 0, // Checksum not validated by SQLite lookup
            text_len: 0,
        };
        let sender = if i % 10 == 0 {
            "special_sender@test.com"
        } else {
            "normal@test.com"
        };
        engine
            .index_message(&msg_id, &header, &format!("Test Subject {}", i), sender)
            .unwrap();
    }

    // 2. Verify that the compression tracker triggered and generated a new index
    let new_dict_id = engine.compression_manager.get_active_dict_id();
    assert!(
        new_dict_id > 0,
        "Dictionary should have been regenerated from high entropy corpus"
    );

    // 3. Store new emails under the new dictionary index
    let new_msg_id = "new_gen_msg";
    let new_email =
        b"From: after_gen@test.com\r\nSubject: New Era\r\n\r\nThis uses the new dictionary.";
    engine
        .store_email(new_msg_id, owner_acl, new_email)
        .await
        .unwrap();

    let header = MailHeader {
        dict_id: new_dict_id,
        acl_id: owner_acl,
        original_checksum: 0,
        text_len: 0,
    };
    engine
        .index_message(new_msg_id, &header, "New Era", "after_gen@test.com")
        .unwrap();

    // 4. Retrieve by various things in the index
    let subject_matches = engine.search_by_subject(owner_acl, "New Era").unwrap();
    assert_eq!(subject_matches.len(), 1);
    assert_eq!(subject_matches[0], new_msg_id);

    let sender_matches = engine
        .search_by_sender(owner_acl, "special_sender@test.com")
        .unwrap();
    assert_eq!(sender_matches.len(), 500); // 5,000 emails where i % 10 == 0 -> 500 matches

    // 5. Test User Access Pass/Fail
    let owner_fetch = engine.get_email("mass_msg_5").await;
    assert!(
        owner_fetch.is_ok(),
        "Owner should successfully read their own email"
    );

    let attacker_fetch = engine.authorize_and_get_dict("mass_msg_5", attacker_acl);
    assert!(
        matches!(attacker_fetch, Err(LumeError::AccessDenied)),
        "Attacker must fail the ACL check"
    );

    // 6. Delete Emails
    engine.delete_email("mass_msg_10", owner_acl).await.unwrap();

    let attacker_delete = engine.delete_email("mass_msg_11", attacker_acl).await;
    assert!(
        matches!(attacker_delete, Err(LumeError::AccessDenied)),
        "Attacker cannot delete others' emails"
    );

    // Verify the email is truly gone from storage and index
    let search_after_delete = engine.authorize_and_get_dict("mass_msg_10", owner_acl);
    assert!(
        matches!(search_after_delete, Err(LumeError::AccessDenied)),
        "Deleted email should fail index lookup"
    );

    let _ = std::fs::remove_dir_all(&test_dir);
}
