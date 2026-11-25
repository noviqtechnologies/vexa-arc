use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::io::Write;
use std::path::Path;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::evaluator::{parse_signed_policy, parse_trusted_policy_keys, PolicyConfig};

pub const KEY_ROTATION_SIGNATURE_DOMAIN: &[u8] = b"VEXA-ARC-KEY-ROTATION-V1\0";
const TRUST_STATE_INTEGRITY_DOMAIN: &[u8] = b"VEXA-ARC-TRUST-STATE-V1\0";

/// Signed, administrator-authorized key rotation and revocation envelope.
/// Must be signed by an already-trusted, non-revoked active key.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyRotationEnvelope {
    pub format_version: u32,
    pub algorithm: String,
    pub authorizing_key_id: String,
    pub rotation_sequence: u64,
    pub issued_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    #[serde(default)]
    pub add_keys: BTreeMap<String, String>,
    #[serde(default)]
    pub revoke_key_ids: Vec<String>,
    pub signature: String,
}

/// Integrity-protected endpoint trust anchor state persisted in `.arc/policy-state.json`.
///
/// Trust can ONLY be bootstrapped out-of-band by an administrator (`arc policy trust-init`
/// or `ARC_POLICY_TRUSTED_PUBLIC_KEYS`) and can ONLY be modified via signed
/// `KeyRotationEnvelope`s authorized by an active trusted key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyTrustStore {
    pub format_version: u32,
    /// Active Ed25519 public keys (`key_id -> 64-char hex`).
    pub active_keys: BTreeMap<String, String>,
    /// Permanently revoked key IDs (monotonically growing; revoked keys can never be re-added).
    #[serde(default)]
    pub revoked_key_ids: BTreeSet<String>,
    /// Monotonic minimum accepted signed-policy sequence number (also mirrored as `min_sequence`).
    pub min_sequence: u64,
    /// Monotonic strictly increasing key-rotation sequence number.
    #[serde(default)]
    pub rotation_sequence: u64,
    /// Last successful sync timestamp (RFC 3339).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub synced_at: Option<String>,
    /// Canonical SHA-256 integrity digest over the trust state fields above.
    pub state_sha256: String,
}

impl PolicyTrustStore {
    /// Bootstrap a new trust store from an administrator-provisioned key specification
    /// (`key-id:hex-pubkey[,key-id2:hex-pubkey2]`).
    pub fn from_root_keys_str(raw: &str, min_sequence: u64) -> Result<Self, String> {
        let parsed = parse_trusted_policy_keys(raw)?;
        let mut active_keys = BTreeMap::new();
        for (k, v) in parsed {
            active_keys.insert(k, hex::encode(v));
        }
        let mut store = Self {
            format_version: 2,
            active_keys,
            revoked_key_ids: BTreeSet::new(),
            min_sequence,
            rotation_sequence: 0,
            synced_at: None,
            state_sha256: String::new(),
        };
        store.recompute_integrity_hash();
        Ok(store)
    }

    fn compute_integrity_hash(&self) -> String {
        let canonical_doc = serde_json::json!({
            "format_version": self.format_version,
            "active_keys": &self.active_keys,
            "revoked_key_ids": &self.revoked_key_ids,
            "min_sequence": self.min_sequence,
            "rotation_sequence": self.rotation_sequence,
        });
        let bytes = serde_jcs::to_vec(&canonical_doc)
            .or_else(|_| serde_json::to_vec(&canonical_doc))
            .unwrap_or_default();
        let mut hasher = Sha256::new();
        hasher.update(TRUST_STATE_INTEGRITY_DOMAIN);
        hasher.update(&bytes);
        hex::encode(hasher.finalize())
    }

    pub fn recompute_integrity_hash(&mut self) {
        self.state_sha256 = self.compute_integrity_hash();
    }

    pub fn verify_integrity(&self) -> Result<(), String> {
        if self.format_version != 2 {
            return Err(format!(
                "Unsupported policy trust state format_version {}",
                self.format_version
            ));
        }
        if self.active_keys.is_empty() {
            return Err("Policy trust store has no active keys".to_string());
        }
        for revoked in &self.revoked_key_ids {
            if self.active_keys.contains_key(revoked) {
                return Err(format!(
                    "Corrupted trust store: key '{revoked}' is both active and revoked"
                ));
            }
        }
        let expected = self.compute_integrity_hash();
        if self.state_sha256 != expected {
            return Err(
                "Policy trust state integrity check failed (state_sha256 mismatch); possible local tampering"
                    .to_string(),
            );
        }
        Ok(())
    }

    /// Convert active non-revoked keys into the map expected by `parse_signed_policy`.
    pub fn active_key_bytes(&self) -> Result<HashMap<String, Vec<u8>>, String> {
        let mut out = HashMap::new();
        for (kid, hex_key) in &self.active_keys {
            if self.revoked_key_ids.contains(kid) {
                continue;
            }
            let bytes = hex::decode(hex_key)
                .map_err(|e| format!("invalid active key hex for '{kid}': {e}"))?;
            if bytes.len() != 32 {
                return Err(format!("active key '{kid}' must be 32 bytes"));
            }
            out.insert(kid.clone(), bytes);
        }
        if out.is_empty() {
            return Err("no active non-revoked policy keys available".to_string());
        }
        Ok(out)
    }

    /// Apply a signed `KeyRotationEnvelope` authorized by an existing active trusted key.
    /// Supports overlap (adding new key(s) while keeping old key(s)) and explicit revocation.
    pub fn apply_key_rotation(
        &mut self,
        envelope_json: &str,
        now_unix_ms: u64,
    ) -> Result<(), String> {
        self.verify_integrity()?;

        let env: KeyRotationEnvelope = serde_json::from_str(envelope_json)
            .map_err(|e| format!("invalid key rotation envelope: {e}"))?;

        if env.format_version != 1 || env.algorithm != "Ed25519" {
            return Err("unsupported key rotation format or signature algorithm".to_string());
        }
        if env.rotation_sequence <= self.rotation_sequence {
            return Err(format!(
                "key rotation rollback/replay rejected: sequence {} <= current {}",
                env.rotation_sequence, self.rotation_sequence
            ));
        }
        if env.issued_at_unix_ms > now_unix_ms.saturating_add(300_000) {
            return Err(
                "key rotation issue time is more than five minutes in the future".to_string(),
            );
        }
        if env.expires_at_unix_ms <= env.issued_at_unix_ms || env.expires_at_unix_ms <= now_unix_ms
        {
            return Err(
                "key rotation envelope is expired or has invalid validity window".to_string(),
            );
        }
        if self.revoked_key_ids.contains(&env.authorizing_key_id) {
            return Err(format!(
                "key rotation rejected: authorizing key '{}' is revoked",
                env.authorizing_key_id
            ));
        }
        let auth_pub_hex = self
            .active_keys
            .get(&env.authorizing_key_id)
            .ok_or_else(|| {
                format!(
                "key rotation rejected: authorizing key '{}' is not in the trusted active key set",
                env.authorizing_key_id
            )
            })?;
        let auth_pub_bytes =
            hex::decode(auth_pub_hex).map_err(|e| format!("corrupted authorizing key hex: {e}"))?;
        let signature = hex::decode(&env.signature)
            .map_err(|e| format!("key rotation signature is not valid hex: {e}"))?;
        if signature.len() != 64 {
            return Err("Ed25519 key rotation signature must be exactly 64 bytes".to_string());
        }

        let signed_document = serde_json::json!({
            "format_version": env.format_version,
            "algorithm": &env.algorithm,
            "authorizing_key_id": &env.authorizing_key_id,
            "rotation_sequence": env.rotation_sequence,
            "issued_at_unix_ms": env.issued_at_unix_ms,
            "expires_at_unix_ms": env.expires_at_unix_ms,
            "add_keys": &env.add_keys,
            "revoke_key_ids": &env.revoke_key_ids,
        });
        let canonical = serde_jcs::to_vec(&signed_document)
            .map_err(|e| format!("cannot canonicalize key rotation document: {e}"))?;
        let mut signed_bytes = KEY_ROTATION_SIGNATURE_DOMAIN.to_vec();
        signed_bytes.extend_from_slice(&canonical);

        ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &auth_pub_bytes)
            .verify(&signed_bytes, &signature)
            .map_err(|_| "key rotation signature verification failed".to_string())?;

        // Stage mutations so validation failures leave trust store completely unchanged
        let mut next_active = self.active_keys.clone();
        let mut next_revoked = self.revoked_key_ids.clone();

        for (kid, pub_hex) in &env.add_keys {
            if kid.is_empty()
                || !kid
                    .chars()
                    .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'))
            {
                return Err(format!("invalid key id '{kid}' in key rotation"));
            }
            if next_revoked.contains(kid) {
                return Err(format!(
                    "key rotation rejected: cannot re-add previously revoked key '{kid}'"
                ));
            }
            let raw_bytes = hex::decode(pub_hex)
                .map_err(|e| format!("invalid public key hex for '{kid}': {e}"))?;
            if raw_bytes.len() != 32 {
                return Err(format!(
                    "Ed25519 public key '{kid}' must be exactly 32 bytes"
                ));
            }
            next_active.insert(kid.clone(), pub_hex.to_ascii_lowercase());
        }

        for rev_kid in &env.revoke_key_ids {
            next_active.remove(rev_kid);
            next_revoked.insert(rev_kid.clone());
        }

        if next_active.is_empty() {
            return Err(
                "key rotation rejected: cannot revoke all active keys (at least one active key must remain)"
                    .to_string(),
            );
        }

        self.active_keys = next_active;
        self.revoked_key_ids = next_revoked;
        self.rotation_sequence = env.rotation_sequence;
        self.recompute_integrity_hash();
        Ok(())
    }

    /// Verify a signed policy envelope strictly against this anchored trust store
    /// and advance `min_sequence` upon success.
    pub fn verify_and_advance_policy(
        &mut self,
        envelope_json: &str,
        now_unix_ms: u64,
    ) -> Result<(PolicyConfig, u64), String> {
        self.verify_integrity()?;
        let env_val: serde_json::Value = serde_json::from_str(envelope_json)
            .map_err(|e| format!("invalid signed policy JSON: {e}"))?;
        let key_id = env_val
            .get("key_id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "signed policy missing key_id".to_string())?;
        if self.revoked_key_ids.contains(key_id) {
            return Err(format!(
                "signed policy rejected: signing key '{key_id}' has been revoked"
            ));
        }
        let seq = env_val
            .get("sequence")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| "signed policy missing sequence".to_string())?;

        let active_keys = self.active_key_bytes()?;
        let policy =
            parse_signed_policy(envelope_json, &active_keys, self.min_sequence, now_unix_ms)?;
        if seq > self.min_sequence {
            self.min_sequence = seq;
        }
        self.synced_at = Some(chrono::Utc::now().to_rfc3339());
        self.recompute_integrity_hash();
        Ok((policy, seq))
    }

    /// Detects a legacy v1 `.arc/policy-state.json` (which stored `trusted_key` without
    /// `format_version` or `state_sha256`). Returns the persisted `min_sequence` (defaulting to 0)
    /// when the content matches the legacy v1 schema.
    pub fn detect_legacy_v1_str(content: &str) -> Option<u64> {
        let val: serde_json::Value = serde_json::from_str(content).ok()?;
        let obj = val.as_object()?;
        if obj.contains_key("format_version") || obj.contains_key("state_sha256") {
            return None;
        }
        if obj.get("trusted_key").and_then(|v| v.as_str()).is_some() {
            let min_seq = obj
                .get("min_sequence")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            return Some(min_seq);
        }
        None
    }

    /// Detects a legacy v1 `.arc/policy-state.json` on disk (refusing symlinks).
    pub fn detect_legacy_v1_file(path: &Path) -> Option<u64> {
        let meta = fs::symlink_metadata(path).ok()?;
        if meta.file_type().is_symlink() {
            return None;
        }
        let content = fs::read_to_string(path).ok()?;
        Self::detect_legacy_v1_str(&content)
    }

    /// Load and verify a persisted trust store from disk (rejecting symlinks and integrity mismatches).
    pub fn load_verified(path: &Path) -> Result<Self, String> {
        if !path.exists() {
            return Err(format!(
                "Policy trust state file '{}' does not exist",
                path.display()
            ));
        }
        let meta = fs::symlink_metadata(path)
            .map_err(|e| format!("Failed to inspect '{}': {e}", path.display()))?;
        if meta.file_type().is_symlink() {
            return Err(format!(
                "Refusing to read symlinked trust state file '{}'",
                path.display()
            ));
        }
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read '{}': {e}", path.display()))?;
        let store: Self = match serde_json::from_str(&content) {
            Ok(s) => s,
            Err(e) => {
                if Self::detect_legacy_v1_str(&content).is_some() {
                    return Err(format!(
                        "Legacy v1 policy trust state '{}' is incompatible with v2 integrity verification (missing format_version/state_sha256). Re-bootstrap with `arc policy trust-init --root-key <key-id:hex> --force` or `arc setup --root-key <key-id:hex>`.",
                        path.display()
                    ));
                }
                return Err(format!(
                    "Malformed policy trust state '{}': {e}",
                    path.display()
                ));
            }
        };
        store.verify_integrity()?;
        Ok(store)
    }

    /// Atomically write this integrity-protected trust store to disk (temp file + fsync + rename).
    pub fn save_atomic(&self, path: &Path) -> Result<(), String> {
        self.verify_integrity()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("Failed to create '{}': {e}", parent.display()))?;
        }
        if path.exists() {
            let meta = fs::symlink_metadata(path)
                .map_err(|e| format!("Failed to inspect '{}': {e}", path.display()))?;
            if meta.file_type().is_symlink() {
                return Err(format!(
                    "Refusing to overwrite symlinked trust state file '{}'",
                    path.display()
                ));
            }
        }

        let json = serde_json::to_string_pretty(self)
            .map_err(|e| format!("Failed to serialize trust state: {e}"))?;
        atomic_write_bytes(path, json.as_bytes())
    }
}

/// Atomically writes bytes to `path` via a sibling temp file, `sync_all`, and `rename`,
/// refusing to follow symlinks.
pub fn atomic_write_bytes(path: &Path, data: &[u8]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create '{}': {e}", parent.display()))?;
    }
    if path.exists() {
        let meta = fs::symlink_metadata(path)
            .map_err(|e| format!("Failed to inspect '{}': {e}", path.display()))?;
        if meta.file_type().is_symlink() {
            return Err(format!(
                "Refusing to overwrite symlink '{}'",
                path.display()
            ));
        }
    }

    let tmp_name = format!(
        ".{}.tmp.{}.{}",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("arc-state"),
        std::process::id(),
        uuid::Uuid::now_v7()
    );
    let tmp_path = path.with_file_name(tmp_name);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(|e| format!("Failed to create temp file '{}': {e}", tmp_path.display()))?;
        f.write_all(data)
            .map_err(|e| format!("Failed to write temp file: {e}"))?;
        f.sync_all()
            .map_err(|e| format!("Failed to fsync temp file: {e}"))?;
    }
    #[cfg(not(unix))]
    {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
            .map_err(|e| format!("Failed to create temp file '{}': {e}", tmp_path.display()))?;
        f.write_all(data)
            .map_err(|e| format!("Failed to write temp file: {e}"))?;
        f.sync_all()
            .map_err(|e| format!("Failed to fsync temp file: {e}"))?;
    }

    if let Err(e) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(format!(
            "Failed to atomically replace '{}': {e}",
            path.display()
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    fn make_keypair(seed_byte: u8) -> (Ed25519KeyPair, String) {
        let seed = [seed_byte; 32];
        let kp = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
        let pub_hex = hex::encode(kp.public_key().as_ref());
        (kp, pub_hex)
    }

    fn sign_policy_envelope(
        kp: &Ed25519KeyPair,
        key_id: &str,
        sequence: u64,
        issued_at: u64,
        expires_at: u64,
        payload: serde_json::Value,
    ) -> String {
        let doc = serde_json::json!({
            "format_version": 1,
            "algorithm": "Ed25519",
            "key_id": key_id,
            "sequence": sequence,
            "issued_at_unix_ms": issued_at,
            "expires_at_unix_ms": expires_at,
            "payload": payload,
        });
        let canonical = serde_jcs::to_vec(&doc).unwrap();
        let mut msg = b"VEXA-ARC-POLICY-V1\0".to_vec();
        msg.extend_from_slice(&canonical);
        let sig = hex::encode(kp.sign(&msg).as_ref());
        serde_json::json!({
            "format_version": 1,
            "algorithm": "Ed25519",
            "key_id": key_id,
            "sequence": sequence,
            "issued_at_unix_ms": issued_at,
            "expires_at_unix_ms": expires_at,
            "payload": payload,
            "signature": sig,
        })
        .to_string()
    }

    fn sign_rotation_envelope(
        authorizing_kp: &Ed25519KeyPair,
        authorizing_key_id: &str,
        rotation_sequence: u64,
        issued_at: u64,
        expires_at: u64,
        add_keys: BTreeMap<String, String>,
        revoke_key_ids: Vec<String>,
    ) -> String {
        let doc = serde_json::json!({
            "format_version": 1,
            "algorithm": "Ed25519",
            "authorizing_key_id": authorizing_key_id,
            "rotation_sequence": rotation_sequence,
            "issued_at_unix_ms": issued_at,
            "expires_at_unix_ms": expires_at,
            "add_keys": add_keys,
            "revoke_key_ids": revoke_key_ids,
        });
        let canonical = serde_jcs::to_vec(&doc).unwrap();
        let mut msg = KEY_ROTATION_SIGNATURE_DOMAIN.to_vec();
        msg.extend_from_slice(&canonical);
        let sig = hex::encode(authorizing_kp.sign(&msg).as_ref());
        serde_json::json!({
            "format_version": 1,
            "algorithm": "Ed25519",
            "authorizing_key_id": authorizing_key_id,
            "rotation_sequence": rotation_sequence,
            "issued_at_unix_ms": issued_at,
            "expires_at_unix_ms": expires_at,
            "add_keys": add_keys,
            "revoke_key_ids": revoke_key_ids,
            "signature": sig,
        })
        .to_string()
    }

    #[test]
    fn rejects_unanchored_attacker_key_and_supports_authorized_rotation_and_revocation() {
        let now = 1_800_000_000_000u64;
        let exp = now + 3_600_000;

        let (kp_a, pub_a) = make_keypair(0x11);
        let (kp_b, pub_b) = make_keypair(0x22);
        let (kp_attacker, pub_attacker) = make_keypair(0x99);

        // 1. Bootstrap trust strictly from administrator-provisioned root key A
        let mut store =
            PolicyTrustStore::from_root_keys_str(&format!("root-a:{pub_a}"), 1).unwrap();

        // 2. Valid policy seq 1 signed by key A succeeds
        let enforce_payload = serde_json::to_value(PolicyConfig::default()).unwrap();
        let pol_a1 = sign_policy_envelope(&kp_a, "root-a", 1, now, exp, enforce_payload.clone());
        let (_, seq1) = store.verify_and_advance_policy(&pol_a1, now).unwrap();
        assert_eq!(seq1, 1);

        // 3. Compromised server returns valid policy seq 5 signed by attacker key -> MUST BE REJECTED
        let pol_attacker = sign_policy_envelope(
            &kp_attacker,
            "attacker-k",
            5,
            now,
            exp,
            enforce_payload.clone(),
        );
        let err = store
            .verify_and_advance_policy(&pol_attacker, now)
            .unwrap_err();
        assert!(err.contains("not trusted"), "err={err}");

        // 4. Attacker attempts self-signed key rotation -> MUST BE REJECTED
        let mut evil_add = BTreeMap::new();
        evil_add.insert("attacker-k".to_string(), pub_attacker.clone());
        let evil_rot =
            sign_rotation_envelope(&kp_attacker, "attacker-k", 1, now, exp, evil_add, vec![]);
        let err_rot = store.apply_key_rotation(&evil_rot, now).unwrap_err();
        assert!(
            err_rot.contains("not in the trusted active key set"),
            "err={err_rot}"
        );

        // 5. Legitimate A-authorized rotation adds key B (overlap window: A and B both valid)
        let mut add_b = BTreeMap::new();
        add_b.insert("root-b".to_string(), pub_b.clone());
        let rot_add_b = sign_rotation_envelope(&kp_a, "root-a", 1, now, exp, add_b, vec![]);
        store.apply_key_rotation(&rot_add_b, now).unwrap();

        // 6. Policy seq 2 signed by B now succeeds
        let pol_b2 = sign_policy_envelope(&kp_b, "root-b", 2, now, exp, enforce_payload.clone());
        let (_, seq2) = store.verify_and_advance_policy(&pol_b2, now).unwrap();
        assert_eq!(seq2, 2);

        // 7. Legitimate B-authorized rotation revokes key A
        let rot_revoke_a = sign_rotation_envelope(
            &kp_b,
            "root-b",
            2,
            now,
            exp,
            BTreeMap::new(),
            vec!["root-a".to_string()],
        );
        store.apply_key_rotation(&rot_revoke_a, now).unwrap();

        // 8. Policy seq 3 signed by revoked key A MUST BE REJECTED
        let pol_a3 = sign_policy_envelope(&kp_a, "root-a", 3, now, exp, enforce_payload);
        let err_rev = store.verify_and_advance_policy(&pol_a3, now).unwrap_err();
        assert!(err_rev.contains("revoked"), "err={err_rev}");

        // 9. Attempting to re-add revoked key A MUST BE REJECTED
        let mut readd_a = BTreeMap::new();
        readd_a.insert("root-a".to_string(), pub_a.clone());
        let rot_readd = sign_rotation_envelope(&kp_b, "root-b", 3, now, exp, readd_a, vec![]);
        assert!(store
            .apply_key_rotation(&rot_readd, now)
            .unwrap_err()
            .contains("previously revoked"));

        // 10. Attempting to replay old rotation_sequence MUST BE REJECTED
        let rot_replay =
            sign_rotation_envelope(&kp_b, "root-b", 2, now, exp, BTreeMap::new(), vec![]);
        assert!(store
            .apply_key_rotation(&rot_replay, now)
            .unwrap_err()
            .contains("rollback/replay"));

        // 11. Atomic save + tamper detection
        let tmp =
            std::env::temp_dir().join(format!("arc_trust_test_{}.json", uuid::Uuid::now_v7()));
        store.save_atomic(&tmp).unwrap();
        let loaded = PolicyTrustStore::load_verified(&tmp).unwrap();
        assert_eq!(loaded, store);

        // Tamper min_sequence on disk -> integrity check fails closed
        let mut tampered: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&tmp).unwrap()).unwrap();
        tampered["min_sequence"] = serde_json::json!(0);
        fs::write(&tmp, serde_json::to_string_pretty(&tampered).unwrap()).unwrap();
        let tamper_err = PolicyTrustStore::load_verified(&tmp).unwrap_err();
        assert!(
            tamper_err.contains("integrity check failed"),
            "err={tamper_err}"
        );

        let _ = fs::remove_file(&tmp);
    }

    #[test]
    fn load_verified_reports_actionable_error_for_legacy_v1_state() {
        let tmp =
            std::env::temp_dir().join(format!("arc_trust_legacy_v1_{}.json", uuid::Uuid::now_v7()));
        fs::write(
            &tmp,
            r#"{
  "min_sequence": 4,
  "synced_at": "2026-11-20T15:38:45Z",
  "trusted_key": "vexa-org:0130edd539192513284ad4446293a1b52b2d92db5e84a3bdfb441978293eece7"
}"#,
        )
        .unwrap();

        assert_eq!(PolicyTrustStore::detect_legacy_v1_file(&tmp), Some(4));

        let err = PolicyTrustStore::load_verified(&tmp).unwrap_err();
        assert!(
            err.contains("Legacy v1 policy trust state"),
            "unexpected err={err}"
        );
        assert!(
            err.contains("arc policy trust-init --root-key"),
            "missing remediation hint in err={err}"
        );

        let _ = fs::remove_file(&tmp);
    }
}
