# FBSDetector NAS PCAP Reverse-Tracking Report

## Scope

This note classifies the public `FBSDetector` NAS traces by the suspicious NAS event that appears to trigger the warning. The goal is analysis and reporting only: which trace corresponds to which abnormal LTE/NAS behavior, and what effect that behavior is intended to cause.

Analysis basis:

1. `FBSDetector.zip` extracted locally under `%TEMP%\FBSDetector_v4\FBSDetector`
2. `dataset/NAS_PCAP_logs/*.pcap`
3. `dataset/NAS_PCAP_logs/attach_reject.xml`
4. `dataset/NAS_PCAP_logs/tau_reject.xml`
5. `dataset/signatures/pltl/NAS/english_description.txt`
6. `dataset/signatures/pltl/NAS/*` PLTL trigger files

Important limitation:

- `attach_reject` and `tau_reject` have PDML/XML evidence, so their message sequences can be verified directly.
- The other NAS traces do not ship with PDML/XML here, so they are classified from the public signature names and `english_description.txt`.

## Executive Summary

| Trace | Primary suspicious NAS event | Likely effect | Confidence | Basis |
| --- | --- | --- | --- | --- |
| `attach_reject.pcap` | `Attach Reject (0x44)` | Attach denial, forced registration failure, possible downgrade path | High | PDML/XML + PLTL description |
| `authentication_failure.pcap` | `Authentication Failure (0x5c)` | Desynchronization-driven denial or forced re-attach behavior | Medium | PLTL description |
| `emm_information.pcap` | `EMM Information` sent without authentication/ciphering | Plaintext spoofing opportunity for operator/network text | Medium | PLTL description |
| `imei_catching.pcap` | `Identity Request` for IMEI | Device identifier exposure | Medium | PLTL description |
| `imsi_catching.pcap` | `Identity Request` for IMSI | Subscriber identifier exposure, stepping stone for later attacks | Medium | PLTL description |
| `malformed_identity_request.pcap` | Invalid or malformed `Identity Request` | Identifier leakage on some devices | Medium | PLTL description |
| `null_encryption.pcap` | Network chooses null encryption | Loss of NAS confidentiality through plaintext exposure risk | Medium | PLTL description |
| `service_reject.pcap` | `Service Reject` | Denial of service against service access | Medium | PLTL description |
| `tau_reject.pcap` | `Tracking Area Update Reject (0x4b)` | Forced detach / denial of service during TAU handling | High | PDML/XML + PLTL description |

Note:

- The NAS PLTL directory also contains `numb_attack`, but there is no matching `numb_attack.pcap` in `dataset/NAS_PCAP_logs`.

## Detailed Findings

### 1. `attach_reject.pcap`

PLTL trigger:

```text
(!(attach_reject))
```

Public description:

```text
attach_reject -> If an attach reject is encountered, the user could have been potentially downgraded.
```

Direct PDML/XML evidence shows repeated attach attempts that terminate in `Attach Reject (0x44)`.

Representative sequences:

1. Straight reject after attach:
   - `Attach request (0x41)` at `attach_reject.xml:29992`
   - `Attach reject (0x44)` at `attach_reject.xml:30318`
   - Cause `PLMN not allowed (11)` at `attach_reject.xml:30320`

2. IMSI disclosure followed by reject:
   - `Attach request (0x41)` at `attach_reject.xml:48949`
   - `Identity request (0x55)` at `attach_reject.xml:49252`
   - `Identity response (0x56)` at `attach_reject.xml:49373`
   - `Attach reject (0x44)` at `attach_reject.xml:49504`
   - Cause `PLMN not allowed (11)` at `attach_reject.xml:49506`

3. Partial authentication/security flow followed by reject:
   - `Attach request (0x41)` at `attach_reject.xml:82530`
   - `Authentication request (0x52)` at `attach_reject.xml:82833`
   - `Authentication response (0x53)` at `attach_reject.xml:82966`
   - `Security mode command (0x5d)` at `attach_reject.xml:83257`
   - `Attach reject (0x44)` at `attach_reject.xml:83550`
   - Cause `Implicitly detached (10)` at `attach_reject.xml:83552`

Observed causes in this trace:

- `PLMN not allowed (11)`
- `Implicitly detached (10)`

Interpretation:

- The suspicious point is the appearance of `Attach Reject`.
- In this trace, the reject is not a one-off packet: it appears repeatedly after different partial procedures, including after identifier disclosure and after authentication/security exchanges.
- For reporting purposes, this trace can be summarized as: **"registration attempt is terminated by Attach Reject, producing attach failure / downgrade-like denial behavior."**

### 2. `tau_reject.pcap`

PLTL trigger:

```text
(!(tracking_area_update_reject))
```

Public description:

```text
tau_reject -> Similar to service reject, Phoenix is also triggered when the TAU reject message is received as it has also been shown to cause DoS attacks.
```

Direct PDML/XML evidence shows repeated `Tracking area update reject (0x4b)` events, typically with cause `Implicitly detached (10)`.

Representative sequences:

1. Authentication completes, then TAU is rejected:
   - `Attach request (0x41)` at `tau_reject.xml:27695`
   - `Authentication request (0x52)` at `tau_reject.xml:27998`
   - `Authentication response (0x53)` at `tau_reject.xml:28131`
   - `Security mode command (0x5d)` at `tau_reject.xml:28259`
   - `Tracking area update reject (0x4b)` at `tau_reject.xml:30168`
   - Cause `Implicitly detached (10)` at `tau_reject.xml:30170`
   - `EMM status (0x60)` at `tau_reject.xml:30294`
   - Cause `Message type not compatible with the protocol state (98)` at `tau_reject.xml:30296`

2. Identity disclosure followed by TAU reject:
   - `Attach request (0x41)` at `tau_reject.xml:58624`
   - `Identity request (0x55)` at `tau_reject.xml:58950`
   - `Identity response (0x56)` at `tau_reject.xml:59075`
   - `Tracking area update reject (0x4b)` at `tau_reject.xml:59206`
   - Cause `Implicitly detached (10)` at `tau_reject.xml:59208`
   - `EMM status (0x60)` at `tau_reject.xml:59332`
   - Cause `Message type not compatible with the protocol state (98)` at `tau_reject.xml:59334`

3. Identity + authentication + security flow followed by TAU reject:
   - `Attach request (0x41)` at `tau_reject.xml:73691`
   - `Identity request (0x55)` at `tau_reject.xml:74017`
   - `Identity response (0x56)` at `tau_reject.xml:74142`
   - `Authentication request (0x52)` at `tau_reject.xml:74273`
   - `Authentication response (0x53)` at `tau_reject.xml:74410`
   - `Tracking area update reject (0x4b)` at `tau_reject.xml:74534`
   - Cause `Implicitly detached (10)` at `tau_reject.xml:74536`

Observed causes in this trace:

- `Implicitly detached (10)` on repeated TAU rejects
- `Message type not compatible with the protocol state (98)` in follow-up `EMM status`
- `Synch failure (21)` appears earlier during an authentication failure sequence

Interpretation:

- The suspicious point is the appearance of `Tracking Area Update Reject`.
- The repeated `Implicitly detached (10)` outcome and the follow-up `EMM status (98)` strongly suggest state-machine disruption rather than a normal successful mobility update.
- For reporting purposes, this trace can be summarized as: **"TAU handling is driven into reject/detach behavior, producing mobility-layer denial of service."**

## Signature-Based Classification for the Remaining NAS Traces

These traces do not have accompanying PDML/XML in the released package here, so the classification below comes from the public PLTL directory and its English descriptions.

### 3. `authentication_failure.pcap`

PLTL:

```text
(!(authentication_failure))
```

Meaning:

- Suspicious event: `Authentication Failure`
- Public interpretation: possible attacker-induced desynchronization
- Report wording: **"This trace is classified as an authentication-failure/desynchronization case."**

### 4. `emm_information.pcap`

PLTL:

```text
(!(emm_information_not_authenticated_and_ciphered))
```

Meaning:

- Suspicious event: `EMM Information` sent before authentication/ciphering protection
- Public interpretation: plaintext EMM information can be spoofed
- Report wording: **"This trace is classified as plaintext EMM Information exposure/spoofing risk."**

### 5. `imei_catching.pcap`

PLTL:

```text
(!(identity_request_IMEI))
```

Meaning:

- Suspicious event: `Identity Request` asks for IMEI
- Public interpretation: device identifier exposure
- Report wording: **"This trace is classified as IMEI-catching / device identifier leakage."**

### 6. `imsi_catching.pcap`

PLTL:

```text
(!(identity_request_IMSI))
```

Meaning:

- Suspicious event: `Identity Request` asks for IMSI
- Public interpretation: subscriber identifier exposure and stepping stone for later targeting
- Report wording: **"This trace is classified as IMSI-catching / permanent subscriber identifier leakage."**

### 7. `malformed_identity_request.pcap`

PLTL:

```text
(!(identity_request_not_well_formed))
```

Meaning:

- Suspicious event: malformed or invalid `Identity Request`
- Public interpretation: some devices may leak identifiers under malformed requests
- Report wording: **"This trace is classified as malformed identity request leading to identifier leakage risk."**

### 8. `null_encryption.pcap`

PLTL:

```text
(!(MME_null_encryption_chosen))
```

Meaning:

- Suspicious event: network selects null encryption
- Public interpretation: privacy/security degradation, including possible exposure of NAS traffic
- Report wording: **"This trace is classified as null-encryption selection / confidentiality downgrade."**

### 9. `service_reject.pcap`

PLTL:

```text
(!(service_reject))
```

Meaning:

- Suspicious event: `Service Reject`
- Public interpretation: denial of service against service access
- Report wording: **"This trace is classified as service-reject-driven denial of service."**

## Short Report-Friendly Sentences

If you need one-line labels for a table or paper draft, these are safe to reuse:

- `attach_reject.pcap`: abnormal `Attach Reject` causes registration failure and potential downgrade-like denial.
- `authentication_failure.pcap`: authentication failure sequence consistent with desynchronization-driven disruption.
- `emm_information.pcap`: plaintext `EMM Information` exposure that could be spoofed.
- `imei_catching.pcap`: `Identity Request` reveals IMEI.
- `imsi_catching.pcap`: `Identity Request` reveals IMSI.
- `malformed_identity_request.pcap`: malformed identity request linked to identifier leakage risk.
- `null_encryption.pcap`: network chooses null encryption, weakening NAS confidentiality.
- `service_reject.pcap`: `Service Reject` used as a denial-of-service condition.
- `tau_reject.pcap`: repeated `Tracking Area Update Reject` drives detach/DoS-like behavior.

## Bottom Line

For this dataset, the "where the attack happens" answer is usually the first suspicious NAS control message:

- `Attach Reject` for `attach_reject.pcap`
- `Authentication Failure` for `authentication_failure.pcap`
- unauthenticated/plaintext `EMM Information` for `emm_information.pcap`
- `Identity Request(IMSI/IMEI)` for the identifier-catching traces
- malformed `Identity Request` for `malformed_identity_request.pcap`
- null encryption selection for `null_encryption.pcap`
- `Service Reject` for `service_reject.pcap`
- `Tracking Area Update Reject` for `tau_reject.pcap`

That is the cleanest reporting lens if the purpose is to explain which message in the LTE NAS flow carries the suspicious behavior.
