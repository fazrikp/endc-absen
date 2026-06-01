import csv
import contextlib
import io
import json
import os
import shutil
import sqlite3
import uuid
from datetime import datetime
from pathlib import Path

from flask import Flask, flash, g, jsonify, redirect, render_template, request, send_file, url_for
from werkzeug.utils import secure_filename
import pyodbc

from crp_tool import (
    DEFAULT_AES_PASSWORD,
    aes_decrypt,
    aes_encrypt,
    analyze_crp,
    looks_like_attendance_text,
    try_brute_xor,
    xor_decrypt,
)


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "web_data"
UPLOAD_DIR = DATA_DIR / "uploads"
OUTPUT_DIR = DATA_DIR / "outputs"
LOG_DIR = DATA_DIR / "logs"
DB_PATH = DATA_DIR / "app.db"

ALLOWED_EXTENSIONS = {"crp", "txt", "csv", "bin", "mdb", "accdb"}
RUNS_PER_PAGE = 8
LOGS_PER_PAGE = 12
MDB_PAGE_SIZE = 25


app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "crp-extract-web-secret")
app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024


def ensure_dirs():
    for path in (DATA_DIR, UPLOAD_DIR, OUTPUT_DIR, LOG_DIR):
        path.mkdir(parents=True, exist_ok=True)


def get_db():
    if "db" not in g:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        g.db = conn
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    ensure_dirs()
    conn = sqlite3.connect(DB_PATH)
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            public_id TEXT UNIQUE NOT NULL,
            original_name TEXT NOT NULL,
            stored_input_name TEXT NOT NULL,
            stored_output_name TEXT NOT NULL,
            input_path TEXT NOT NULL,
            output_path TEXT NOT NULL,
            mode TEXT NOT NULL,
            method TEXT NOT NULL,
            key_used TEXT,
            status TEXT NOT NULL,
            input_size INTEGER NOT NULL,
            output_size INTEGER,
            section_count INTEGER DEFAULT 0,
            preview_text TEXT,
            error_message TEXT,
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER,
            level TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(run_id) REFERENCES runs(id)
        );
        """
    )
    existing_columns = {
        row[1] for row in conn.execute("PRAGMA table_info(runs)").fetchall()
    }
    for column_name, column_type in [
        ("reencrypt_path", "TEXT"),
        ("reencrypt_name", "TEXT"),
        ("reencrypt_size", "INTEGER"),
    ]:
        if column_name not in existing_columns:
            conn.execute(f"ALTER TABLE runs ADD COLUMN {column_name} {column_type}")
    conn.commit()
    conn.close()


def log_event(run_id, level, message):
    conn = get_db()
    conn.execute(
        "INSERT INTO logs (run_id, level, message, created_at) VALUES (?, ?, ?, ?)",
        (run_id, level, message, datetime.utcnow().isoformat(timespec="seconds")),
    )
    conn.commit()


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def parse_attendance_rows(text):
    rows = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parts = [part.strip() for part in stripped.split(",")]
        if len(parts) < 3:
            continue
        rows.append(
            {
                "count": parts[0] if len(parts) > 0 else "",
                "enroll_number": parts[1] if len(parts) > 1 else "",
                "verify_mode": parts[2] if len(parts) > 2 else "",
                "in_out_mode": parts[3] if len(parts) > 3 else "",
                "date": parts[4] if len(parts) > 4 else "",
                "work_code": parts[5] if len(parts) > 5 else "",
                "reserved": parts[6] if len(parts) > 6 else "",
                "raw": stripped,
            }
        )
    return rows


def summarize_text(data):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None, []
    if not looks_like_attendance_text(data):
        return text, []
    return text, parse_attendance_rows(text)


def rows_to_csv_text(rows):
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["Count", "EnrollNumber", "VerifyMode", "InOutMode", "Date", "WorkCode", "Reserved"])
    for row in rows:
        writer.writerow([
            row.get("count", ""),
            row.get("enroll_number", ""),
            row.get("verify_mode", ""),
            row.get("in_out_mode", ""),
            row.get("date", ""),
            row.get("work_code", ""),
            row.get("reserved", ""),
        ])
    return buffer.getvalue()


def rows_to_attendance_text(rows):
    lines = []
    for row in rows:
        original_raw = row.get("original_raw")
        current_values = [
            row.get("count", ""),
            row.get("enroll_number", ""),
            row.get("verify_mode", ""),
            row.get("in_out_mode", ""),
            row.get("date", ""),
            row.get("work_code", ""),
            row.get("reserved", ""),
        ]
        if original_raw is not None:
            original_values = [part.strip() for part in original_raw.split(",")]
            while original_values and original_values[-1] == "":
                original_values.pop()
            compact_current = current_values[:]
            while compact_current and compact_current[-1] == "":
                compact_current.pop()
            if compact_current == original_values:
                lines.append(original_raw)
                continue

        while current_values and current_values[-1] == "":
            current_values.pop()
        lines.append(",".join(current_values))
    return "\r\n".join(lines) + ("\r\n" if lines else "")


def mdb_quote(identifier):
    return f"[{str(identifier).replace(']', ']]')}]"


def open_mdb_connection(db_path):
    return pyodbc.connect(
        f"DRIVER={{Microsoft Access Driver (*.mdb, *.accdb)}};DBQ={db_path};",
        autocommit=False,
    )


def mdb_table_names(db_path):
    connection = open_mdb_connection(db_path)
    try:
        cursor = connection.cursor()
        tables = []
        for row in cursor.tables(tableType="TABLE"):
            table_name = getattr(row, "table_name", None) or getattr(row, "TABLE_NAME", None)
            if not table_name or table_name.startswith("MSys") or table_name.startswith("~"):
                continue
            tables.append(table_name)
        return tables
    finally:
        connection.close()


def mdb_column_defs(db_path, table_name):
    connection = open_mdb_connection(db_path)
    try:
        cursor = connection.cursor()
        primary_keys = set()
        try:
            for row in cursor.primaryKeys(table=table_name):
                column_name = getattr(row, "column_name", None) or getattr(row, "COLUMN_NAME", None)
                if column_name:
                    primary_keys.add(column_name)
        except Exception:
            primary_keys = set()

        columns = []
        for index, row in enumerate(cursor.columns(table=table_name)):
            column_name = getattr(row, "column_name", None) or getattr(row, "COLUMN_NAME", None)
            if not column_name:
                continue
            type_name = getattr(row, "type_name", None) or getattr(row, "TYPE_NAME", None) or ""
            columns.append(
                {
                    "name": column_name,
                    "field_id": f"col_{index}",
                    "original_field_id": f"orig_col_{index}",
                    "type_name": type_name,
                    "is_pk": column_name in primary_keys,
                }
            )
        return columns
    finally:
        connection.close()


def mdb_table_rows(db_path, table_name):
    columns = mdb_column_defs(db_path, table_name)
    connection = open_mdb_connection(db_path)
    try:
        cursor = connection.cursor()
        cursor.execute(f"SELECT * FROM {mdb_quote(table_name)}")
        fetched = cursor.fetchall()
        rows = []
        for row in fetched:
            row_dict = {}
            for index, column in enumerate(columns):
                value = row[index] if index < len(row) else None
                row_dict[column["name"]] = "" if value is None else str(value)
            rows.append(row_dict)
        return rows
    finally:
        connection.close()


def mdb_load_view(db_path, selected_table=None, page=1):
    tables = mdb_table_names(db_path)
    if not tables:
        return {
            "tables": [],
            "selected_table": None,
            "columns": [],
            "rows": [],
            "total_rows": 0,
            "page": 1,
            "total_pages": 1,
            "page_size": MDB_PAGE_SIZE,
            "primary_keys": [],
        }

    if selected_table not in tables:
        selected_table = tables[0]

    columns = mdb_column_defs(db_path, selected_table)
    rows = mdb_table_rows(db_path, selected_table)
    total_rows = len(rows)
    total_pages = max(1, (total_rows + MDB_PAGE_SIZE - 1) // MDB_PAGE_SIZE)
    page = min(max(1, page), total_pages)
    start = (page - 1) * MDB_PAGE_SIZE
    end = start + MDB_PAGE_SIZE
    page_rows = rows[start:end]

    for index, row in enumerate(page_rows, start=start):
        row["_row_index"] = index

    return {
        "tables": tables,
        "selected_table": selected_table,
        "columns": columns,
        "rows": page_rows,
        "total_rows": total_rows,
        "page": page,
        "total_pages": total_pages,
        "page_size": MDB_PAGE_SIZE,
        "primary_keys": [column["name"] for column in columns if column["is_pk"]],
    }


def mdb_write_rows(db_path, table_name, columns, rows):
    if not rows:
        return

    editable_columns = [column["name"] for column in columns]
    primary_keys = [column["name"] for column in columns if column["is_pk"]]
    where_columns = primary_keys if primary_keys else editable_columns

    connection = open_mdb_connection(db_path)
    try:
        cursor = connection.cursor()
        for row in rows:
            set_columns = editable_columns[:]
            set_sql = ", ".join(f"{mdb_quote(column)} = ?" for column in set_columns)
            where_sql = " AND ".join(f"{mdb_quote(column)} = ?" for column in where_columns)
            set_values = [row[column] for column in set_columns]
            where_values = [row[f"orig_{column}"] for column in where_columns]
            sql = f"UPDATE {mdb_quote(table_name)} SET {set_sql} WHERE {where_sql}"
            cursor.execute(sql, set_values + where_values)
        connection.commit()
    finally:
        connection.close()


def get_search_term():
    return request.args.get("q", "").strip()


def get_page_value(name, default=1):
    try:
        value = int(request.args.get(name, default))
    except (TypeError, ValueError):
        value = default
    return max(1, value)


def paginate_runs(conn, search_term, page):
    where_clause = ""
    params = []
    if search_term:
        where_clause = (
            "WHERE original_name LIKE ? OR mode LIKE ? OR method LIKE ? OR status LIKE ? OR COALESCE(key_used, '') LIKE ?"
        )
        like = f"%{search_term}%"
        params = [like, like, like, like, like]

    total = conn.execute(f"SELECT COUNT(*) FROM runs {where_clause}", params).fetchone()[0]
    total_pages = max(1, (total + RUNS_PER_PAGE - 1) // RUNS_PER_PAGE)
    page = min(page, total_pages)
    offset = (page - 1) * RUNS_PER_PAGE
    rows = conn.execute(
        f"SELECT * FROM runs {where_clause} ORDER BY id DESC LIMIT ? OFFSET ?",
        params + [RUNS_PER_PAGE, offset],
    ).fetchall()
    return rows, total, total_pages, page


def paginate_logs(conn, search_term, page):
    where_clause = ""
    params = []
    if search_term:
        where_clause = "WHERE logs.message LIKE ? OR logs.level LIKE ? OR COALESCE(runs.original_name, '') LIKE ?"
        like = f"%{search_term}%"
        params = [like, like, like]

    total = conn.execute(
        f"""
        SELECT COUNT(*)
        FROM logs
        LEFT JOIN runs ON runs.id = logs.run_id
        {where_clause}
        """,
        params,
    ).fetchone()[0]
    total_pages = max(1, (total + LOGS_PER_PAGE - 1) // LOGS_PER_PAGE)
    page = min(page, total_pages)
    offset = (page - 1) * LOGS_PER_PAGE
    rows = conn.execute(
        f"""
        SELECT logs.*, runs.original_name
        FROM logs
        LEFT JOIN runs ON runs.id = logs.run_id
        {where_clause}
        ORDER BY logs.id DESC
        LIMIT ? OFFSET ?
        """,
        params + [LOGS_PER_PAGE, offset],
    ).fetchall()
    return rows, total, total_pages, page


def load_run_payload(run):
    output_path = Path(run["output_path"])
    if not output_path.exists():
        return "", [], b""
    data = output_path.read_bytes()
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = ""
    rows = parse_attendance_rows(text) if text else []
    return text, rows, data


def persist_edited_text(run, conn, raw_text, re_encrypt):
    normalized_text = raw_text.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n")
    output_path = Path(run["output_path"])
    output_path.write_bytes(normalized_text.encode("utf-8"))

    text_preview, rows = summarize_text(normalized_text.encode("utf-8"))
    section_count = len(rows)
    conn.execute(
        """
        UPDATE runs
        SET output_size = ?, section_count = ?, preview_text = ?, status = ?
        WHERE id = ?
        """,
        (
            output_path.stat().st_size,
            section_count,
            text_preview,
            "success",
            run["id"],
        ),
    )
    conn.commit()
    log_event(run["id"], "success", "Editor disimpan ke file output.")

    if re_encrypt and run["mode"] == "decrypt":
        reencrypt_name = f"{Path(run['original_name']).stem}_edited_roundtrip.crp"
        reencrypt_path = OUTPUT_DIR / f"{run['public_id']}_{secure_filename(reencrypt_name)}"
        key_used = run["key_used"] or DEFAULT_AES_PASSWORD
        if run["method"] == "aes":
            encrypted = aes_encrypt(normalized_text.encode("utf-8"), key_used)
        elif run["method"] == "xor":
            try:
                if str(key_used).startswith("0x"):
                    xor_value = int(str(key_used), 16)
                else:
                    xor_value = int(str(key_used))
            except Exception:
                xor_value = 0x55
            encrypted = xor_decrypt(normalized_text.encode("utf-8"), xor_value)
        else:
            encrypted = normalized_text.encode("utf-8")
        reencrypt_path.write_bytes(encrypted)
        conn.execute(
            """
            UPDATE runs
            SET reencrypt_path = ?, reencrypt_name = ?, reencrypt_size = ?
            WHERE id = ?
            """,
            (str(reencrypt_path), reencrypt_name, reencrypt_path.stat().st_size, run["id"]),
        )
        conn.commit()
        log_event(run["id"], "success", f"Re-encrypt dibuat: {reencrypt_name}")
        return "Editor disimpan dan file re-encrypt dibuat."

    return "Perubahan berhasil disimpan."


def render_dashboard(selected_run=None, selected_logs=None, section_rows=None, section_preview=None, mdb_view=None):
    conn = get_db()
    search_term = get_search_term()
    history_page = get_page_value("history_page")
    log_page = get_page_value("log_page")
    runs, runs_total, runs_total_pages, history_page = paginate_runs(conn, search_term, history_page)
    logs, logs_total, logs_total_pages, log_page = paginate_logs(conn, search_term, log_page)

    if selected_logs is None and selected_run is not None:
        selected_logs = conn.execute(
            "SELECT * FROM logs WHERE run_id = ? ORDER BY id ASC",
            (selected_run["id"],),
        ).fetchall()

    if selected_run is not None and selected_run["mode"] == "mdb":
        mdb_page = get_page_value("mdb_page")
        selected_table = request.args.get("table")
        db_path = Path(selected_run["output_path"])
        if not db_path.exists():
            db_path = Path(selected_run["input_path"])
        mdb_view = mdb_load_view(str(db_path), selected_table=selected_table, page=mdb_page)

    return render_template(
        "index.html",
        runs=runs,
        logs=logs,
        selected_run=selected_run,
        selected_logs=selected_logs,
        section_rows=section_rows or [],
        section_preview=section_preview or "",
        default_key=DEFAULT_AES_PASSWORD,
        search_term=search_term,
        history_page=history_page,
        history_total_pages=runs_total_pages,
        history_total=runs_total,
        log_page=log_page,
        log_total_pages=logs_total_pages,
        log_total=logs_total,
        current_endpoint=request.endpoint or "index",
        selected_run_id=selected_run["public_id"] if selected_run is not None else None,
        mdb_view=mdb_view or {},
    )


def process_uploaded_file(input_path, mode, method, key, xor_key, output_path):
    data = Path(input_path).read_bytes()

    if mode == "decrypt":
        if method == "auto":
            xor_candidates = try_brute_xor(data)
            if xor_candidates:
                return xor_candidates[0][1], "xor", f"0x{xor_candidates[0][0]:02X}"
            for candidate in [DEFAULT_AES_PASSWORD, "1234567890123456", "admin12345678901", "P208FINGERPRINT0"]:
                try:
                    decrypted = aes_decrypt(data, candidate)
                    if looks_like_attendance_text(decrypted):
                        return decrypted, "aes", candidate
                except Exception:
                    continue
            raise ValueError("Auto-detect gagal. Gunakan key AES atau XOR manual.")
        if method == "aes":
            chosen_key = key or DEFAULT_AES_PASSWORD
            decrypted = aes_decrypt(data, chosen_key)
            return decrypted, "aes", chosen_key
        if method == "xor":
            chosen_xor = 0x55 if xor_key is None else xor_key
            return xor_decrypt(data, chosen_xor), "xor", f"0x{chosen_xor:02X}"
        raise ValueError("Metode decrypt tidak dikenal.")

    if mode == "encrypt":
        if method == "aes":
            chosen_key = key or DEFAULT_AES_PASSWORD
            return aes_encrypt(data, chosen_key), "aes", chosen_key
        if method == "xor":
            chosen_xor = 0x55 if xor_key is None else xor_key
            return xor_decrypt(data, chosen_xor), "xor", f"0x{chosen_xor:02X}"
        raise ValueError("Metode encrypt tidak dikenal.")

    raise ValueError("Mode tidak dikenal.")


@app.teardown_appcontext
def teardown_db(exception):
    close_db(exception)


@app.route("/", methods=["GET"])
def index():
    return render_dashboard()


@app.route("/process", methods=["POST"])
def process():
    if "file" not in request.files:
        flash("File belum dipilih.", "danger")
        return redirect(url_for("index"))

    uploaded = request.files["file"]
    if not uploaded.filename:
        flash("Nama file kosong.", "danger")
        return redirect(url_for("index"))

    if not allowed_file(uploaded.filename):
        flash("Ekstensi file tidak didukung.", "danger")
        return redirect(url_for("index"))

    mode = request.form.get("mode", "decrypt")
    method = request.form.get("method", "auto")
    aes_key = request.form.get("aes_key", "").strip() or None
    xor_key_raw = request.form.get("xor_key", "").strip()
    xor_key = int(xor_key_raw) if xor_key_raw else None
    output_name = request.form.get("output_name", "").strip()

    ensure_dirs()
    original_name = secure_filename(uploaded.filename)
    file_ext = Path(original_name).suffix.lower().lstrip(".")
    if file_ext in {"mdb", "accdb"}:
        mode = "mdb"
    run_id = str(uuid.uuid4())
    stored_input_name = f"{run_id}_{original_name}"
    input_path = UPLOAD_DIR / stored_input_name
    uploaded.save(input_path)

    if not output_name:
        base_name = Path(original_name).stem
        if mode == "mdb":
            output_name = f"{base_name}_edited.mdb"
        else:
            output_name = f"{base_name}_{mode}.out" if mode != "analyze" else f"{base_name}_analysis.txt"
    stored_output_name = f"{run_id}_{secure_filename(output_name)}"
    output_path = OUTPUT_DIR / stored_output_name

    if mode == "mdb":
        shutil.copy2(input_path, output_path)
        conn = get_db()
        created_at = datetime.utcnow().isoformat(timespec="seconds")
        cursor = conn.execute(
            """
            INSERT INTO runs (
                public_id, original_name, stored_input_name, stored_output_name,
                input_path, output_path, mode, method, key_used, status,
                input_size, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                original_name,
                stored_input_name,
                stored_output_name,
                str(input_path),
                str(output_path),
                mode,
                method,
                None,
                "processing",
                input_path.stat().st_size,
                created_at,
            ),
        )
        run_db_id = cursor.lastrowid
        conn.commit()
        tables = mdb_table_names(str(input_path))
        result_bytes = output_path.read_bytes()
        preview_text = json.dumps({"tables": tables}, ensure_ascii=False)
        conn.execute(
            """
            UPDATE runs
            SET method = ?, key_used = ?, status = ?, output_size = ?, section_count = ?, preview_text = ?
            WHERE id = ?
            """,
            (
                "mdb",
                None,
                "success",
                len(result_bytes),
                len(tables),
                preview_text,
                run_db_id,
            ),
        )
        conn.commit()
        log_event(run_db_id, "info", f"File diterima: {original_name}")
        log_event(run_db_id, "info", f"Mode={mode}, Method={method}")
        log_event(run_db_id, "success", f"MDB siap diedit. Tables: {', '.join(tables) if tables else '-'}")
        flash("File MDB berhasil dimuat.", "success")
        return redirect(url_for("result", run_id=run_id))

    conn = get_db()
    created_at = datetime.utcnow().isoformat(timespec="seconds")
    cursor = conn.execute(
        """
        INSERT INTO runs (
            public_id, original_name, stored_input_name, stored_output_name,
            input_path, output_path, mode, method, key_used, status,
            input_size, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            run_id,
            original_name,
            stored_input_name,
            stored_output_name,
            str(input_path),
            str(output_path),
            mode,
            method,
            aes_key if method == "aes" else (f"{xor_key}" if xor_key is not None else None),
            "processing",
            input_path.stat().st_size,
            created_at,
        ),
    )
    run_db_id = cursor.lastrowid
    conn.commit()
    log_event(run_db_id, "info", f"File diterima: {original_name}")
    log_event(run_db_id, "info", f"Mode={mode}, Method={method}")

    try:
        if mode == "analyze":
            analysis_buffer = io.StringIO()
            with contextlib.redirect_stdout(analysis_buffer):
                analyze_crp(str(input_path))
            analysis_text = analysis_buffer.getvalue()
            result_bytes = analysis_text.encode("utf-8")
            actual_method = "analyze"
            key_used = None
            log_event(run_db_id, "info", "Analisis CRP selesai.")
        else:
            result_bytes, actual_method, key_used = process_uploaded_file(
                input_path=input_path,
                mode=mode,
                method=method,
                key=aes_key,
                xor_key=xor_key,
                output_path=output_path,
            )
        output_path.write_bytes(result_bytes)

        text_preview, rows = summarize_text(result_bytes)
        section_count = len(rows)
        preview_text = text_preview if text_preview else None
        output_size = len(result_bytes)
        conn.execute(
            """
            UPDATE runs
            SET method = ?, key_used = ?, status = ?, output_size = ?, section_count = ?, preview_text = ?
            WHERE id = ?
            """,
            (
                actual_method,
                key_used,
                "success",
                output_size,
                section_count,
                preview_text,
                run_db_id,
            ),
        )
        conn.commit()
        log_event(run_db_id, "success", f"Proses selesai. Output tersimpan: {stored_output_name}")
        if section_count:
            log_event(run_db_id, "success", f"Terdeteksi {section_count} baris attendance.")
        flash("File berhasil diproses.", "success")
        return redirect(url_for("result", run_id=run_id))
    except Exception as exc:
        conn.execute(
            "UPDATE runs SET status = ?, error_message = ? WHERE id = ?",
            ("error", str(exc), run_db_id),
        )
        conn.commit()
        log_event(run_db_id, "error", str(exc))
        flash(f"Gagal memproses file: {exc}", "danger")
        return redirect(url_for("index"))


@app.route("/result/<run_id>", methods=["GET"])
def result(run_id):
    conn = get_db()
    run = conn.execute("SELECT * FROM runs WHERE public_id = ?", (run_id,)).fetchone()
    if run is None:
        flash("Hasil tidak ditemukan.", "warning")
        return redirect(url_for("index"))

    preview_text, section_rows, _ = load_run_payload(run)
    if not preview_text:
        preview_text = run["preview_text"] or ""
        if preview_text and not section_rows:
            section_rows = parse_attendance_rows(preview_text)

    return render_dashboard(selected_run=run, section_rows=section_rows, section_preview=preview_text)


@app.route("/download/<run_id>", methods=["GET"])
def download(run_id):
    conn = get_db()
    run = conn.execute("SELECT * FROM runs WHERE public_id = ?", (run_id,)).fetchone()
    if run is None:
        flash("File output tidak ditemukan.", "warning")
        return redirect(url_for("index"))
    return send_file(run["output_path"], as_attachment=True, download_name=Path(run["output_path"]).name)


@app.route("/download_mdb/<run_id>", methods=["GET"])
def download_mdb(run_id):
    conn = get_db()
    run = conn.execute("SELECT * FROM runs WHERE public_id = ?", (run_id,)).fetchone()
    if run is None:
        flash("File MDB tidak ditemukan.", "warning")
        return redirect(url_for("index"))
    if run["mode"] != "mdb":
        flash("Route ini hanya untuk file MDB.", "warning")
        return redirect(url_for("result", run_id=run_id))
    return send_file(run["output_path"], as_attachment=True, download_name=Path(run["output_path"]).name)


@app.route("/download_reencrypt/<run_id>", methods=["GET"])
def download_reencrypt(run_id):
    conn = get_db()
    run = conn.execute("SELECT * FROM runs WHERE public_id = ?", (run_id,)).fetchone()
    if run is None or not run["reencrypt_path"]:
        flash("File re-encrypt belum tersedia.", "warning")
        return redirect(url_for("result", run_id=run_id))
    reencrypt_path = Path(run["reencrypt_path"])
    if not reencrypt_path.exists():
        flash("File re-encrypt tidak ditemukan di disk.", "warning")
        return redirect(url_for("result", run_id=run_id))
    return send_file(reencrypt_path, as_attachment=True, download_name=run["reencrypt_name"] or reencrypt_path.name)


@app.route("/export_csv/<run_id>", methods=["GET"])
def export_csv(run_id):
    conn = get_db()
    run = conn.execute("SELECT * FROM runs WHERE public_id = ?", (run_id,)).fetchone()
    if run is None:
        flash("Data CSV tidak ditemukan.", "warning")
        return redirect(url_for("index"))

    preview_text, section_rows, _ = load_run_payload(run)
    if not section_rows and preview_text:
        section_rows = parse_attendance_rows(preview_text)

    csv_text = rows_to_csv_text(section_rows)
    buffer = io.BytesIO(csv_text.encode("utf-8-sig"))
    buffer.seek(0)
    filename = f"{Path(run['original_name']).stem}_section_frame.csv"
    return send_file(buffer, as_attachment=True, download_name=filename, mimetype="text/csv")


@app.route("/save_edit/<run_id>", methods=["POST"])
def save_edit(run_id):
    conn = get_db()
    run = conn.execute("SELECT * FROM runs WHERE public_id = ?", (run_id,)).fetchone()
    if run is None:
        flash("Data yang akan diedit tidak ditemukan.", "warning")
        return redirect(url_for("index"))

    raw_text = request.form.get("raw_text", "")
    re_encrypt = request.form.get("re_encrypt") == "1"

    if not raw_text.strip():
        flash("Isi editor tidak boleh kosong.", "danger")
        return redirect(url_for("result", run_id=run_id))
    message = persist_edited_text(run, conn, raw_text, re_encrypt)
    flash(message, "success")

    return redirect(url_for("result", run_id=run_id))


@app.route("/save_rows/<run_id>", methods=["POST"])
def save_rows(run_id):
    conn = get_db()
    run = conn.execute("SELECT * FROM runs WHERE public_id = ?", (run_id,)).fetchone()
    if run is None:
        flash("Data yang akan diedit tidak ditemukan.", "warning")
        return redirect(url_for("index"))

    counts = request.form.getlist("count")
    enroll_numbers = request.form.getlist("enroll_number")
    verify_modes = request.form.getlist("verify_mode")
    in_out_modes = request.form.getlist("in_out_mode")
    dates = request.form.getlist("date")
    work_codes = request.form.getlist("work_code")
    reserveds = request.form.getlist("reserved")
    original_raws = request.form.getlist("original_raw")
    re_encrypt = request.form.get("re_encrypt") == "1"

    row_count = min(
        len(counts),
        len(enroll_numbers),
        len(verify_modes),
        len(in_out_modes),
        len(dates),
        len(work_codes),
        len(reserveds),
        len(original_raws),
    )
    rows = []
    for index in range(row_count):
        rows.append(
            {
                "count": counts[index].strip(),
                "enroll_number": enroll_numbers[index].strip(),
                "verify_mode": verify_modes[index].strip(),
                "in_out_mode": in_out_modes[index].strip(),
                "date": dates[index].strip(),
                "work_code": work_codes[index].strip(),
                "reserved": reserveds[index].strip(),
                "original_raw": original_raws[index],
            }
        )

    if not rows:
        flash("Tidak ada baris yang bisa disimpan.", "danger")
        return redirect(url_for("result", run_id=run_id))

    raw_text = rows_to_attendance_text(rows)
    message = persist_edited_text(run, conn, raw_text, re_encrypt)
    flash(f"{message} Dari editor tabel.", "success")
    return redirect(url_for("result", run_id=run_id))


@app.route("/save_mdb_rows/<run_id>/<table_name>", methods=["POST"])
def save_mdb_rows(run_id, table_name):
    conn = get_db()
    run = conn.execute("SELECT * FROM runs WHERE public_id = ?", (run_id,)).fetchone()
    if run is None or run["mode"] != "mdb":
        flash("File MDB tidak ditemukan.", "warning")
        return redirect(url_for("index"))

    db_path = Path(run["output_path"])
    if not db_path.exists():
        db_path = Path(run["input_path"])

    table_names = mdb_table_names(str(db_path))
    if table_name not in table_names:
        flash("Tabel MDB tidak ditemukan.", "warning")
        return redirect(url_for("result", run_id=run_id))

    columns = mdb_column_defs(str(db_path), table_name)
    rows = []
    row_count = len(request.form.getlist(columns[0]["field_id"])) if columns else 0
    if row_count == 0:
        flash("Tidak ada baris MDB yang dikirim.", "danger")
        return redirect(url_for("result", run_id=run_id, table=table_name))

    for index in range(row_count):
        row_data = {}
        for column in columns:
            values = request.form.getlist(column["field_id"])
            originals = request.form.getlist(column["original_field_id"])
            row_data[column["name"]] = values[index].strip() if index < len(values) else ""
            row_data[f"orig_{column['name']}"] = originals[index] if index < len(originals) else ""
        rows.append(row_data)

    mdb_write_rows(str(db_path), table_name, columns, rows)

    output_size = Path(db_path).stat().st_size
    conn.execute(
        "UPDATE runs SET output_size = ?, status = ? WHERE id = ?",
        (output_size, "success", run["id"]),
    )
    conn.commit()
    log_event(run["id"], "success", f"MDB table disimpan: {table_name}")
    flash("Tabel MDB berhasil disimpan.", "success")
    return redirect(url_for("result", run_id=run_id, table=table_name))


@app.route("/api/logs", methods=["GET"])
def api_logs():
    conn = get_db()
    rows = conn.execute(
        "SELECT * FROM logs ORDER BY id DESC LIMIT 100"
    ).fetchall()
    return jsonify([dict(row) for row in rows])


@app.route("/api/mdb_schema/<run_id>/<table_name>", methods=["GET"])
def api_mdb_schema(run_id, table_name):
    conn = get_db()
    run = conn.execute("SELECT * FROM runs WHERE public_id = ?", (run_id,)).fetchone()
    if run is None or run["mode"] != "mdb":
        return jsonify({"error": "Run not found or not an MDB file."}), 404

    db_path = Path(run["output_path"]) if Path(run["output_path"]).exists() else Path(run["input_path"])
    try:
        columns = mdb_column_defs(str(db_path), table_name)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    # Return only the useful fields for the UI
    schema = [
        {"name": c["name"], "type": c.get("type_name", ""), "is_pk": bool(c.get("is_pk", False))}
        for c in columns
    ]
    return jsonify({"table": table_name, "columns": schema})


def main():
    init_db()
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)


if __name__ == "__main__":
    main()