use std::collections::HashMap;

/// Calculates the Shannon entropy H(X) in bits per character.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    let mut freq: HashMap<u8, usize> = HashMap::new();
    for &byte in data {
        *freq.entry(byte).or_insert(0) += 1;
    }

    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in freq.values() {
        let p = count as f64 / len;
        if p > 0.0 {
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Computes charset-aware normalized entropy H_norm = H(X) / log2(|Sigma|).
pub fn normalized_entropy(data: &[u8]) -> f64 {
    if data.len() < 2 {
        return 0.0;
    }

    let raw = shannon_entropy(data);

    // Detect alphabet kind
    let is_hex = data.iter().all(|&b| b.is_ascii_hexdigit());
    let is_base64 = data.iter().all(|&b| {
        b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=' || b == b'-' || b == b'_'
    });

    let alphabet_size: f64 = if is_hex {
        16.0
    } else if is_base64 {
        64.0
    } else {
        256.0
    };

    let max_entropy = alphabet_size.log2();
    if max_entropy > 0.0 {
        raw / max_entropy
    } else {
        0.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_shannon_entropy() {
        assert_eq!(shannon_entropy(b""), 0.0);
        assert_eq!(shannon_entropy(b"aaaaaa"), 0.0);

        // High entropy random string
        let high_entropy = b"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        assert!(shannon_entropy(high_entropy) > 4.5);
    }

    #[test]
    fn test_normalized_entropy() {
        let hex = b"0123456789abcdef";
        let norm = normalized_entropy(hex);
        assert!(norm > 0.9);
    }
}
