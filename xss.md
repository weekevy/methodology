
# Advanced XSS Detection Methodology (Post-Recon)

## 1. Parameter Reflection Analysis
- Inject benign and unique strings like `xss123`, `reflect_test`, or `"><xss>` into each query and body parameter.
- Analyze the response to see where and how the input is reflected:
  - Inside the HTML body as plain text
  - Within HTML tags or attributes
  - Inside inline or external JavaScript
  - Inside JSON responses or JavaScript variables
  - In HTTP headers like `Location`, `Refresh`, etc.

### 🔍 Where to Inject:
- **URL query parameters**: Common in search, filter, and category links. Example: `https://site.com/search?q=xss123`
- **Form inputs (GET/POST)**: Fields like login, signup, comment forms, and feedback. Use intercepting proxy or browser dev tools to modify inputs.
- **Headers**: Often overlooked, especially `Referer`, `User-Agent`, and custom headers. Useful if reflected or logged.
- **URL fragments**: After `#`, especially in SPAs. Example: `https://site.com/#xss123`.
- **Cookies**: Rare but possible if the app reflects or logs cookie values.

## 1.1 Hidden Parameter Discovery
Modern web applications often use hidden or undocumented parameters that aren't visible in the UI but can influence backend logic or rendering.

### 🔍 How to Discover Hidden Parameters:
- **Brute-force using wordlists**: Use tools like `ffuf`, `ParamMiner`, or custom scripts to fuzz for additional parameters.
  - Example: `https://target.com/page?debug=1`, `admin=true`, `user=guest`, `redirect=URL`
- **Check JavaScript and HTML source code**: Look for hardcoded parameter names in scripts, forms, or AJAX requests.
- **Look at network traffic**: Inspect requests in your browser DevTools → Network tab. Hidden parameters are often used in background API calls.
- **Use old backups or archived files**: Look in robots.txt, sitemap.xml, or old JS files for legacy parameters.
- **Try guessable keywords**: Common ones include: `return_url`, `next`, `redirect`, `callback`, `user`, `admin`, `lang`, `theme`, `style`, `query`, `search`, `debug`, `log`, `test`, `jsonp`, `output`, `template`, etc.
- **Use passive tools**: Tools like Burp Suite’s Param Miner extension, or GoBuster with `--append-slash` and custom wordlists can reveal interesting parameters not immediately obvious.

## 2. Context Identification
Determine the **execution context** of the reflected input. This defines how the browser will interpret your payload. Common contexts:
- **HTML context**: Safe if escaped, dangerous if inserted raw into tags like `<div>input</div>`
- **Attribute context**: Your input is part of a tag attribute like `<img src="input">`. Dangerous if it breaks out of quotes.
- **JavaScript context**: Input reflected inside script tags or JS variables. Example: `var a = 'input';`
- **URL/link context**: Inside `href`, `src`, etc. If improperly sanitized, it can lead to JS execution.
- **Event handler context**: If injected into attributes like `onclick`, can lead to code execution: `<button onclick="input">`
- **JSON context**: Reflected in API responses or in JS objects: `{ "name": "input" }`

## 3. Contextual Payload Crafting
Craft payloads that break out of their context and execute code. Examples by context:

### HTML
```html
"><img src=x onerror=alert(1)>
</script><script>alert(1)</script>
```
Explanation: Breaks out of current tag or closes the `<script>` tag to inject your own.

### Attribute
```html
' onerror=alert(1) x='
" autofocus onfocus=alert(1) a="
```
Explanation: Breaks out of quotes and injects an event handler to trigger JavaScript.

### JavaScript
```js
';alert(1);//
";alert(1);//
` ;alert(1)//
```
Explanation: Ends the JS statement or string and starts your own malicious code.

### JSON/JavaScript context
```json
"}]};alert(1)//
"}]}--><script>alert(1)</script>
```
Explanation: Breaks JSON structure or injects tags to execute inside a webpage.

## 4. Filter Evasion Techniques
Use encoding and alternate forms to bypass weak filters or WAFs:
- **HTML entity encoding**:
```html
&#x3C;script&#x3E;alert(1)//&#x3C;/script&#x3E;
```
- **Hex/Unicode/URL encoding**: Bypass naive blacklists.
- **Obscure HTML5 event handlers**: `onpointerover`, `onanimationstart`, `oncut`, etc.
- **Uncommon tags**: `<svg>`, `<math>`, `<details>` often not filtered.
- **JS wrapper bypasses**:
```js
setTimeout('alert(1)',100)
new Function('alert(1)')
```

## 5. Behavioral Trigger Testing
Some payloads only execute under certain conditions:
- **User interaction**:
  - `onmouseover`: triggers when user hovers
  - `onfocus`: when user clicks into a field
  - `onsubmit`: when form is submitted
- **Timed payloads**:
```html
<img src=x onerror="setTimeout(()=>alert(1),1000)">
```
- **Fragment injections**: Try adding payloads to URL hash if frontend logic parses it

## 6. DOM-Based XSS Discovery
Analyze front-end JavaScript:
- **Tainted sources**:
  - `location.href`
  - `document.URL`
  - `location.hash`
  - `window.name`
- **Dangerous sinks**:
  - `innerHTML`, `outerHTML`, `document.write`, `eval`, `Function`
  - Template rendering functions
- **Example:**
```js
let userInput = location.search;
document.getElementById("result").innerHTML = userInput;
```
If input isn’t sanitized, XSS is possible.

### 🔍 Where to Look:
- Inline scripts with dynamic content
- Frameworks (Angular, Vue, React with `dangerouslySetInnerHTML`)
- Template injection points (`{{ userInput }}` in JS templates)
- JS files loaded from the server or CDN that process user input

## 7. Advanced Vectors & Exploit Chaining
- Combine multiple vulnerabilities for impact:
  - Open Redirect + Reflected XSS
  - DOM XSS + Misconfigured CSP
  - JSONP endpoint + Callback injection
- Use known gadget chains:
  - jQuery <1.9 and AngularJS sandbox bypasses
- Bypass security headers:
  - CSP bypass via iframe or base64 injection
  - Same-origin abuse via `postMessage`

## 8. Manual Confirmation & Verification
- Test payloads in different browsers (Chrome, Firefox, Safari)
- Confirm if payload needs an action (click, hover, submit)
- Check for persistence: does it stay stored in the app?
- Test for self-replicating XSS (worm-type)
- Try real-world weaponization:
  - Cookie theft via JS (`document.cookie`)
  - Stealing localStorage/sessionStorage
  - Phishing via DOM manipulation
  - Defacing the site temporarily via JS injection

---
## 9. tools can use

 ** dalfox **
 `dalfox file urls.txt -deep-detect --mass --silence` 
 - smart xss scanning/ support get post json headers and blind xss
 - can take inputs from burp logs files urls or stdin
 
 ** XSStrike **
 `python3 xssstrike.py -u 'http://exmaple.com/page?query=param`
 - powerfull fuzzing engine with custom payload generator
 - dom xss detection context analysis , WAF bypassing
 ~ Slower than dalfox for big lists but great for target-specific testing


 ** kxss **
 `cut url.txt | kxss`
 - very fast detects reflected xss by analyzing chrome debug output
 ~ does not inject payload - it's good as a pre-check tool for reflection
  

