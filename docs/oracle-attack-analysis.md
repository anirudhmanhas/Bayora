# Threat Model Analysis: Side-Channel Inference via Defense Oracle Probing

> **Scope**: Bayora POC — Multi-Tenant Adversarial AI Testing Infrastructure  
> **Topic**: Fundamental Security Boundary & Unpreventable Oracle Side-Channel

---

## 1. Executive Summary

The Bayora architecture implements robust defense-in-depth isolation mechanisms:
1. **Payload Sequestration**: Red team payloads are written only to isolated storage (`red_payloads`), while Blue receives state-only responses until test conclusion.
2. **Defensive Shielding**: Blue defense logic is declarative (`blue_logic`), non-executable, and evaluated inside an isolated, no-network `defense-runner` sandbox.
3. **Information Masking**: Red never receives rule names, pattern IDs, or trigger thresholds—only a coarse, generic verdict (`"Blocked by defense policy"`).
4. **Cryptographic Integrity**: Payloads are hashed with SHA-256 and chained into an append-only audit ledger before model inference.

Despite these rigorous boundaries, **there is one fundamental security property this design cannot mathematically prevent**:

> **Red inferring Blue's defensive logic, pattern lists, and thresholds over multiple attempts by observing binary (`allow`/`block`) and ternary (`sanitize`) response patterns.**

---

## 2. Anatomy of the Oracle Attack

Because the gateway must communicate whether a prompt was allowed, blocked, or sanitized, the system acts as an **interactive membership oracle** $O(x) \to \{\text{Allow}, \text{Block}, \text{Sanitize}\}$.

```
+----------+      Prompt x_i       +-----------+   Prompt x_i   +----------------+
|          | --------------------> |           | -------------> | defense-runner |
|          |                       |  GATEWAY  |                |  (blue_logic)  |
|          | <-------------------- |           | <------------- +----------------+
|   RED    |   Generic Verdict:    +-----------+      Verdict:
|   TEAM   |   "Blocked by defense"                   ALLOW / BLOCK / SANITIZE
| (Oracle  |   or Model Response
|  Prober) |
+----------+
     |
     v
[Iterative Statistical Inference & Rule Boundary Reconstruction]
```

### Attack Techniques

### A. Vocabulary & Pattern Sweep (Dichotomy Probing)
An adversarial Red team can isolate specific strings from Blue's pattern lists:
1. Red submits benign baseline prompt:  
   $$x_0 = \text{"Explain the principles of distributed consensus."} \to \text{ALLOW}$$
2. Red submits probe with candidate keyword $k_1$:  
   $$x_1 = \text{"Explain the principles of distributed consensus with bypass."} \to \text{BLOCK}$$
3. Red submits probe with candidate keyword $k_2$:  
   $$x_2 = \text{"Explain the principles of distributed consensus with overflow."} \to \text{ALLOW}$$

**Inference**: The token `"bypass"` belongs to Blue's pattern blocklist, whereas `"overflow"` is either not present or below threshold.

### B. Threshold Probing
If Blue configures a threshold rule ($\text{threshold} = k$ hits):
- Prompt with 1 occurrence of suspicious token $\to \text{ALLOW}$
- Prompt with 2 occurrences of suspicious token $\to \text{ALLOW}$
- Prompt with 3 occurrences of suspicious token $\to \text{BLOCK}$

**Inference**: The defense rule fires at exactly $\text{count} \ge 3$, enabling Red to craft adversarial jailbreaks that keep suspicious tokens at $\le 2$.

### C. Sanitization Mapping
When a rule triggers `"sanitize"`:
- Prompt: `"The database credential is password123."`
- Revealed model response: `"The database credential is [REDACTED]."`

**Inference**: By comparing the returned token positions against the input, Red pinpoints exact string boundaries targeted by Blue's replacement rules.

---

## 3. Why Cryptographic & Network Controls Cannot Prevent This

| Security Layer | What It Successfully Protects | Why It Cannot Prevent Oracle Probing |
| :--- | :--- | :--- |
| **Network Isolation (`defense-net`)** | Prevents lateral TCP connections from Red to `defense-runner`. | The oracle query is legitimately routed through Gateway as part of the intended test protocol. |
| **Read-Only / Separate Volumes** | Prevents Red from reading `blue_logic` on disk. | Information is transmitted through the output channel, not the filesystem. |
| **Information Masking** | Prevents leakage of rule names, metadata, or execution traces. | The 1-bit output ($\text{Allow} / \text{Block}$) provides non-zero Shannon channel capacity ($\approx 1\text{ bit per query}$). |
| **SHA-256 Audit Ledger** | Prevents tampering with payloads or audit history. | Audit logs record that queries occurred; they do not restrict information theoretic leakage. |

As long as the evaluation system answers queries interactively, **every verdict leaks information about the decision boundary**.

---

## 4. Potential Mitigations & Trade-Offs

While complete elimination of oracle inference is impossible in interactive testing environments, the attack can be made significantly more expensive:

1. **Strict Query Quotas & Budgets**:
   - Limit Red to $N$ total submissions per test session.
   - *Trade-off*: Decreases Red's ability to thoroughly test complex model behaviors.

2. **Delayed / Batched Verdict Reveal**:
   - Instead of real-time verdicts, queue all Red submissions and release responses and block statistics only after the session concludes.
   - *Trade-off*: Eliminates real-time feedback loops required for interactive red-teaming.

3. **Differential Privacy / Noisy Verdicts**:
   - Inject randomized threshold jitter or probabilistic blocks on borderline prompts.
   - *Trade-off*: Introduces false positives and reduces evaluation reproducibility.

4. **Response Rate Throttling & Anomaly Detection**:
   - Monitor high-frequency semantic perturbations and throttle sessions exhibiting dictionary-sweep behavior.
   - *Trade-off*: Adds stateful monitoring overhead to the Gateway.

---

## 5. Conclusion

The commit-reveal lifecycle and defense runner architecture in Bayora provide complete isolation of raw payloads, source logic, and execution environments. However, **the primary feedback channel itself acts as a side channel**. Any adversarial evaluation platform must treat rule inference via repeated query observation as an inherent threat, addressed via query budgeting and operational policies rather than network-level isolation alone.
