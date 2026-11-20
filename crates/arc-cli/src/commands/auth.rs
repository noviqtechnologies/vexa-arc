use arc_telemetry::VexaCloudAuth;
use std::time::Duration;

pub fn run_auth_login(token_opt: Option<&str>, api_url: Option<&str>, json: bool) -> bool {
    let base_url = VexaCloudAuth::resolve_api_base_url(api_url);

    let token = match token_opt.map(str::trim).filter(|s| !s.is_empty()) {
        Some(t) => t.to_string(),
        None => match VexaCloudAuth::get_token() {
            Some(t) => t,
            None => {
                eprintln!("[Arc Auth] Error: No token supplied. Pass `--token <vexa_pat_...>` or set `VEXA_TOKEN`.");
                return false;
            }
        },
    };

    let is_pat = token.starts_with("vexasec_")
        || token.starts_with("vexa_pat_")
        || token.starts_with("sktsec_");
    if !is_pat && token.len() < 16 {
        eprintln!(
            "[Arc Auth] Invalid token format. Vexa API tokens start with 'vexasec_' or 'vexa_pat_'."
        );
        return false;
    }

    let mut org_slug = VexaCloudAuth::get_org_slug();
    let mut user_email = None;

    if !VexaCloudAuth::is_offline() {
        if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            let status_url = format!("{}/auth/status", base_url.trim_end_matches('/'));
            let tok_c = token.clone();
            rt.block_on(async {
                if let Ok(client) = reqwest::Client::builder()
                    .timeout(Duration::from_secs(10))
                    .build()
                {
                    if let Ok(resp) = client
                        .get(&status_url)
                        .header("Authorization", format!("Bearer {tok_c}"))
                        .send()
                        .await
                    {
                        if resp.status().is_success() {
                            if let Ok(info) = resp.json::<serde_json::Value>().await {
                                if let Some(o) = info.get("org_slug").and_then(|v| v.as_str()) {
                                    org_slug = Some(o.to_string());
                                }
                                if let Some(e) = info.get("user_email").and_then(|v| v.as_str()) {
                                    user_email = Some(e.to_string());
                                }
                            }
                        }
                    }
                }
            });
        }
    }

    let path = match VexaCloudAuth::save_credentials_with_url(
        &token,
        org_slug.as_deref(),
        user_email.as_deref(),
        Some(&base_url),
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[Arc Auth] {e}");
            return false;
        }
    };

    if json {
        println!(
            "{}",
            serde_json::json!({
                "authenticated": true,
                "org_slug": org_slug,
                "user_email": user_email,
                "credentials_path": path.display().to_string(),
                "api_base_url": base_url,
            })
        );
    } else {
        println!("✔ Authenticated with Vexa Cloud ({base_url})");
        if let Some(ref org) = org_slug {
            println!("  Organization: {org}");
        }
        if let Some(ref email) = user_email {
            println!("  Account:      {email}");
        }
        println!("  Credentials:  {}", path.display());
    }
    true
}

pub fn run_auth_status(api_url: Option<&str>, json: bool) -> bool {
    let base_url = VexaCloudAuth::resolve_api_base_url(api_url);
    let token = VexaCloudAuth::get_token();
    let stored = VexaCloudAuth::load_stored_credentials();
    let cred_path = VexaCloudAuth::credentials_path();

    let Some(tok) = token else {
        if json {
            println!(
                "{}",
                serde_json::json!({
                    "authenticated": false,
                    "cloud_verified": false,
                    "credentials_path": cred_path.display().to_string(),
                    "api_base_url": base_url,
                })
            );
        } else {
            println!("Vexa Cloud Status: Unauthenticated (Local Mode)");
            println!("  Run `arc setup` to connect to Vexa Cloud via browser approval (or `arc auth login --token <vexa_pat_...>` for CI/headless).");
        }
        return true;
    };

    let prefix = if tok.len() >= 12 {
        format!("{}...", &tok[..12])
    } else {
        "token...".to_string()
    };

    let mut org_slug = VexaCloudAuth::get_org_slug();
    let mut user_email = stored.as_ref().and_then(|s| s.user_email.clone());
    let mut tier = Some("Local".to_string());
    let mut cloud_verified = false;

    if !VexaCloudAuth::is_offline() {
        if let Ok(rt) = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            let status_url = format!("{}/auth/status", base_url.trim_end_matches('/'));
            rt.block_on(async {
                if let Ok(client) = reqwest::Client::builder()
                    .timeout(Duration::from_secs(10))
                    .build()
                {
                    if let Ok(resp) = client
                        .get(&status_url)
                        .header("Authorization", format!("Bearer {tok}"))
                        .send()
                        .await
                    {
                        if resp.status().is_success() {
                            if let Ok(info) = resp.json::<serde_json::Value>().await {
                                let is_auth = info
                                    .get("authenticated")
                                    .and_then(|v| v.as_bool())
                                    .unwrap_or(true);
                                if is_auth {
                                    cloud_verified = true;
                                    if let Some(o) = info.get("org_slug").and_then(|v| v.as_str()) {
                                        org_slug = Some(o.to_string());
                                    }
                                    if let Some(e) = info.get("user_email").and_then(|v| v.as_str())
                                    {
                                        user_email = Some(e.to_string());
                                    }
                                    if let Some(t) = info.get("tier").and_then(|v| v.as_str()) {
                                        tier = Some(t.to_string());
                                    }
                                } else if let Some(t) = info.get("tier").and_then(|v| v.as_str()) {
                                    tier = Some(t.to_string());
                                }
                            }
                        }
                    }
                }
            });
        }
    }

    if json {
        println!(
            "{}",
            serde_json::json!({
                "authenticated": true,
                "cloud_verified": cloud_verified,
                "token_prefix": prefix,
                "org_slug": org_slug,
                "user_email": user_email,
                "tier": tier,
                "credentials_path": cred_path.display().to_string(),
                "api_base_url": base_url,
            })
        );
    } else {
        println!(
            "Vexa Cloud Status: Authenticated ({})",
            if cloud_verified {
                "Verified"
            } else {
                "Token Present / Offline"
            }
        );
        println!("  Token:        {prefix}");
        if let Some(ref o) = org_slug {
            println!("  Organization: {o}");
        }
        if let Some(ref t) = tier {
            println!("  Tier:         {t}");
        }
        println!("  Credentials:  {}", cred_path.display());
    }
    true
}

pub fn run_auth_logout(json: bool) -> bool {
    match VexaCloudAuth::logout() {
        Ok(removed) => {
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "success": true,
                        "removed": removed,
                    })
                );
            } else if removed {
                println!("✔ Logged out. Stored Vexa Cloud credentials removed.");
            } else {
                println!("• No stored credentials found.");
            }
            true
        }
        Err(e) => {
            eprintln!("[Arc Auth] {e}");
            false
        }
    }
}
