# Security Log Investigation Report

**Dataset:** `authentication-log-sample.csv` (synthetic)  
**Investigation date range:** 1 August 2026 (UTC)  
**Records analyzed:** 12  
**Track / level:** Cyber Security / Beginner-friendly

## 1. Executive summary

The 12-record synthetic authentication log contains two clear suspicious patterns:
- Three failed password-login attempts for account `stu-117` from `198.51.100.27` in 34 seconds, followed by an `account_lock` event.
- Four failed password-login attempts against four different accounts from `203.0.113.42` in 12 seconds, followed by a `rate_limit` event recorded as `blocked`.

A later successful password login for `stu-311` from `192.0.2.99` on an iOS device is worth reviewing because the same account was among the earlier failures from `203.0.113.42` on an unknown device. The log alone does not establish that the successful login was unauthorized or related to the earlier attempts.

## 2. Data normalization

The source fields were standardized as follows:
- `timestamp` parsed as an ISO-8601 timestamp and represented consistently in UTC (`timestamp_utc`).
- `user_id` trimmed and lowercased.
- `source_ip` trimmed and retained as an IPv4 string.
- `event`, `result`, and `device` trimmed and lowercased.
- No source values were invented or silently changed. The normalized data is in `normalized_authentication_logs.csv`.

All 12 timestamps already included the `Z` UTC marker. The dataset uses the documentation-only IP ranges `192.0.2.0/24`, `198.51.100.0/24`, and `203.0.113.0/24`; they are examples, not evidence of real-world attacker locations.

## 3. Detection rules

| Detection | Rule applied to this sample | Why it matters |
|---|---|---|
| Brute-force indicator | At least 3 failed password logins for the same account from the same IP within 5 minutes | Repeated password guesses against one account |
| Password-spraying indicator | At least 3 distinct accounts targeted by one IP within 1 minute, with failed password logins | One or a small number of passwords may be tried across many accounts |
| Unusual-access review | Successful login for an account previously seen in suspicious failures, especially from a different IP/device | May warrant validation, but a change in IP/device alone is not proof of compromise |

These are simple investigation thresholds for this exercise, not universal production security thresholds.

## 4. Findings and evidence

### Finding A — Possible brute-force activity against `stu-117`

**Evidence**
- `09:03:44`, `09:04:01`, and `09:04:18 UTC`: `password_login` failures for `stu-117`.
- All three events came from `198.51.100.27` and used the `windows` device value.
- `09:05:03 UTC`: an `account_lock` event for `stu-117`, with result `success`.

**Assessment:** The repeated failures meet the defined brute-force indicator. The subsequent successful `account_lock` event indicates that the account-lock action was recorded as successful; it is not a successful login.

### Finding B — Possible password spraying from `203.0.113.42`

**Evidence**
- `09:21:10 UTC`: failure for `stu-209`.
- `09:21:13 UTC`: failure for `stu-311`.
- `09:21:17 UTC`: failure for `stu-415`.
- `09:21:22 UTC`: failure for `stu-502`.
- All four were `password_login` events from `203.0.113.42`, with device `unknown`.
- `09:22:01 UTC`: `rate_limit` event for `stu-209`, result `blocked`.

**Assessment:** One source IP targeted four distinct accounts in 12 seconds, meeting the password-spraying indicator. The rate-limit event suggests a defensive control blocked or limited activity. The log does not reveal which password(s) were attempted.

### Finding C — Successful login requiring validation for `stu-311`

**Evidence**
- `09:21:13 UTC`: failed password login for `stu-311` from `203.0.113.42`, device `unknown`.
- `11:47:09 UTC`: successful password login for `stu-311` from `192.0.2.99`, device `ios`.

**Assessment:** This is an unusual-access review lead because the account appears in the earlier suspicious sequence and later logs in successfully from a different source IP/device. The gap is about 2 hours 26 minutes. The records do not prove that the later login was caused by the earlier activity or that it was malicious.

## 5. Incident timeline

| Time (UTC) | Event | Evidence-based interpretation |
|---|---|---|
| 09:00:12 | `stu-104` password login success from `192.0.2.18` (android) | Baseline successful login |
| 09:03:44–09:04:18 | Three failures for `stu-117` from `198.51.100.27` (windows) | Brute-force indicator |
| 09:05:03 | `account_lock` for `stu-117`, result `success` | Account-lock action recorded successfully |
| 09:21:10–09:21:22 | Four account failures from `203.0.113.42` (unknown device) | Password-spraying indicator |
| 09:22:01 | `rate_limit` for `stu-209`, result `blocked` | Rate-limit control recorded as blocking activity |
| 10:15:32 | `stu-104` refresh-token success from `192.0.2.18` (android) | Successful token refresh |
| 11:47:09 | `stu-311` password login success from `192.0.2.99` (ios) | Unusual-access review lead; not proof of compromise |

## 6. Evidence versus assumptions

**Directly supported by the log**
- Exact timestamps, account IDs, source IPs, event names, results, and device labels.
- Three failed attempts against `stu-117` from one IP within 34 seconds.
- Four different accounts received failed attempts from one IP within 12 seconds.
- An account-lock event and a rate-limit blocked event were recorded.
- `stu-311` later had a successful login from a different IP and device label.

**Not established by this log**
- The attacker's identity, physical location, or motivation.
- Whether any password was correct or exposed.
- Whether the later `stu-311` login was legitimate or compromised.
- Whether the `account_lock` or `rate_limit` controls remained effective beyond the logged events.
- Whether any data was accessed or exfiltrated.

## 7. Recommended containment and logging improvements

1. Preserve the original logs and investigate the relevant account and authentication records.
2. Verify the `stu-117` account-lock state and confirm the account owner can recover access safely.
3. Review `stu-311`'s later login with the account owner; if it is not recognized, revoke active sessions/tokens, reset credentials, and review account activity.
4. Keep rate limiting and account-protection controls enabled; alert on repeated failures across one account and failures spread across multiple accounts.
5. Log a correlation/request ID, authentication method, outcome reason, session/token issuance and revocation, and MFA result where applicable.
6. Synchronize system clocks and retain timestamps in UTC.
7. Avoid logging plaintext passwords, password hashes, session tokens, or other secrets.

## 8. Conclusion

The sample shows one brute-force indicator and one password-spraying indicator, followed by recorded account-lock and rate-limit actions. A later successful login for `stu-311` should be validated, but the available evidence is insufficient to label it a confirmed compromise. This report distinguishes observed events from hypotheses and recommends proportionate follow-up actions.

## 9. Method and limitations

This is a manual, rule-based review of a small synthetic dataset containing 12 rows. The detection thresholds are defined for this exercise. No external IP reputation, geolocation, endpoint, identity-provider, or network telemetry was available. Therefore, conclusions are limited to the supplied records.
