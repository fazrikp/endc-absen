# CRP Extract Web

Versi web berbasis Flask untuk proses `.crp` mesin absensi P208 / ZKTeco clone.

## Fitur

- Upload file `.crp` atau `.txt`
- Upload file `.mdb` / `.accdb` untuk editor Access
- Mode `decrypt`, `encrypt`, dan `analyze`
- Auto-detect AES / XOR
- History file yang diupload
- Tabel hasil `section frame`
- Log proses per file
- Editor MDB row-by-row via ODBC Access driver

## Menjalankan

```powershell
& ".\.venv\Scripts\python.exe" .\web_app.py
```

Buka `http://127.0.0.1:5000` di browser.

## Catatan

- AES default yang tervalidasi pada sample adalah `myKey123`
- Hasil history, output, dan log disimpan di folder `web_data`