#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import json
import logging
import sqlite3
import datetime
import ssl
import email
import concurrent.futures
import traceback
import yaml
from email.header import decode_header
from imapclient import IMAPClient
import requests
from logging.handlers import TimedRotatingFileHandler

# ログディレクトリ
LOG_DIR = "./logs"
os.makedirs(LOG_DIR, exist_ok=True)
log_filename = os.path.join(LOG_DIR, "imap_to_huginn.log")

class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "message": record.getMessage()
        }
        return json.dumps(log_record, ensure_ascii=False)

def gz_rotator(source, dest):
    import gzip
    with open(source, "rb") as sf, gzip.open(dest, "wb") as df:
        df.writelines(sf)
    os.remove(source)

file_handler = TimedRotatingFileHandler(
    log_filename,
    when="midnight",
    interval=1,
    backupCount=30,
    encoding="utf-8"
)
file_handler.suffix = "%Y-%m-%d.gz"
file_handler.rotator = gz_rotator
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(JsonFormatter(datefmt="%Y-%m-%dT%H:%M:%S"))

logger = logging.getLogger("imap_to_huginn")
logger.setLevel(logging.DEBUG)
logger.addHandler(file_handler)
logger.info("ログ設定完了。")

# 設定ファイルの読み込み
def load_config(config_path="config.yaml"):
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        logger.info(f"設定ファイル {config_path} を読み込みました")
        return config
    except Exception as e:
        logger.warning(f"設定ファイルの読み込みに失敗: {e}")
        return {"triggers": []}  # デフォルト設定を返す

# 設定の初期化
config = load_config()
triggers = config.get('triggers', [])

# --- DB初期化 ---
DB_FILE = "processed_emails.db"
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS processed_emails (
            uid TEXT PRIMARY KEY,
            processed_at TEXT
        )
    """)
    conn.commit()
    return conn

def is_processed(conn, uid):
    cursor = conn.cursor()
    cursor.execute("SELECT uid FROM processed_emails WHERE uid = ?", (uid,))
    return cursor.fetchone() is not None

def mark_processed(conn, uid):
    cursor = conn.cursor()
    cursor.execute(
        "INSERT OR IGNORE INTO processed_emails (uid, processed_at) VALUES (?, ?)",
        (uid, datetime.datetime.now(datetime.timezone.utc).isoformat())
    )
    conn.commit()

# --- MIME ヘッダーのデコード ---
def decode_mime_words(s):
    if not s:
        return ""
    decoded_fragments = decode_header(s)
    decoded_string = ""
    for fragment, encoding in decoded_fragments:
        if isinstance(fragment, bytes):
            if encoding:
                try:
                    decoded_string += fragment.decode(encoding, errors="replace")
                    continue
                except Exception:
                    pass
            try:
                decoded_string += fragment.decode("utf-8", errors="replace")
            except Exception:
                decoded_string += fragment.decode("latin-1", errors="replace")
        else:
            decoded_string += fragment
    return decoded_string

def check_exclude_keywords(text, exclude_keywords):
    """
    テキストに除外キーワードが含まれているかチェックする
    
    Args:
        text (str): チェック対象のテキスト
        exclude_keywords (list): 除外キーワードのリスト
    
    Returns:
        bool: 除外キーワードが見つかった場合はTrue、それ以外はFalse
    """
    if not exclude_keywords:
        return False
        
    for keyword in exclude_keywords:
        if keyword in text:
            logger.debug(f"除外キーワード '{keyword}' が検出されました")
            return True
    return False

# --- メール本文を取得 ---
def process_email_content(message):
    raw_subject = message.get('Subject', '')
    subject = decode_mime_words(raw_subject)
    body = ""
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_type() == "text/plain":
                charset = part.get_content_charset() or 'utf-8'
                try:
                    body = part.get_payload(decode=True).decode(charset, errors='replace')
                except Exception:
                    body = part.get_payload(decode=True).decode("utf-8", errors='replace')
                break
    else:
        charset = message.get_content_charset() or 'utf-8'
        try:
            body = message.get_payload(decode=True).decode(charset, errors='replace')
        except Exception:
            body = message.get_payload(decode=True).decode("utf-8", errors='replace')
    return subject, body

# === ここからHuginn連携用 ===

def forward_to_n8n(n8n_webhook_url, subject, body):
    """
    n8nのWebhookにメール情報をPOSTする関数。
    """
    # 静音時間かどうかをチェック
    def is_in_quiet_hours():
        quiet_hours = config.get('quiet_hours', {'start': '02:00', 'end': '04:00'})
        now = datetime.datetime.now()
        current_time = now.strftime('%H:%M')
        quiet_start = quiet_hours.get('start')
        quiet_end = quiet_hours.get('end')
        
        # 開始時刻が終了時刻より前の場合
        if quiet_start <= quiet_end:
            return quiet_start <= current_time <= quiet_end
        # 開始時刻が終了時刻より後の場合（日をまたぐ）
        else:
            return current_time >= quiet_start or current_time <= quiet_end
    
    # 静音時間のフラグ
    is_quiet_hours = is_in_quiet_hours()
    
    # トリガー条件のチェック
    matched_trigger = None
    
    for trigger in triggers:
        target_text = subject if trigger.get('target') == 'subject' else body
        keywords = trigger.get('keywords', [])
        if isinstance(keywords, str):
            keywords = [keywords]
            
        # 除外キーワードのチェック
        exclude_keywords = trigger.get('exclude_keywords', [])
        if check_exclude_keywords(target_text, exclude_keywords):
            logger.info(f"除外キーワードにより転送をスキップ: {subject}")
            return
            
        # キーワードマッチング
        if trigger.get('and_condition', False):
            if not all(keyword in target_text for keyword in keywords):
                continue
        else:
            if not any(keyword in target_text for keyword in keywords):
                continue
                
        # マッチしたら保存して終了
        matched_trigger = trigger
        break
    
    # デフォルトトリガー
    if not matched_trigger:
        matched_trigger = {
            'name': 'other_all',
            'priority': 3,
            'sound': 'default'
        }
    
    # 静音時間内なら優先度を下げる
    adjusted_priority = matched_trigger.get('priority', 3)
    if is_quiet_hours and adjusted_priority > 1:
        adjusted_priority -= 1
    
    # ペイロードに送信
    payload = {
        "subject": subject,
        "body": body,
        "received_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "trigger_name": matched_trigger.get('name', ''),
        "priority": adjusted_priority,
        "original_priority": matched_trigger.get('priority', 3),
        "sound": matched_trigger.get('sound', ''),
        "is_quiet_hours": is_quiet_hours,
        "evaluated_by": "imap_webhook.py"  # 評価元を識別するフラグ
    }
    
    # 環境変数から認証トークンを取得
    auth_token = os.environ.get("N8N_AUTH_TOKEN", "XXXXXXXXXXXX")
    
    headers = {
        "Content-Type": "application/json",
        "X-N8N-Authorization": auth_token
    }
    
    try:
        logger.debug(f"n8nへのPOSTリクエスト送信開始: {n8n_webhook_url}")
        logger.debug(f"ペイロードサイズ: 約{len(json.dumps(payload))}バイト")
        
        resp = requests.post(n8n_webhook_url, json=payload, headers=headers, timeout=5)
        
        if resp.ok:
            logger.info(f"n8n通知成功: {subject}")
            logger.info(f"レスポンス: {resp.text[:100]}")
        else:
            logger.error(f"n8n通知失敗: status={resp.status_code}, body={resp.text}")
            logger.error(f"リクエストヘッダー: {headers}")
    except requests.exceptions.Timeout:
        logger.error(f"n8n通知タイムアウト: {n8n_webhook_url} (5秒)")
    except Exception as e:
        logger.error(f"n8n通知例外: {e}")
        logger.error(f"例外詳細: {traceback.format_exc()}")

def fetch_and_forward(server, db_conn, n8n_webhook_url, mailbox="INBOX"):
    """
    新着メールを取得し、n8nへ非同期で転送する。
    既に処理済みのUIDはスキップし、処理後はDBに登録する。
    """
    start_time = time.time()
    logger.debug("=== fetch_and_forward開始 ===")
    
    try:
        logger.debug(f"フォルダ選択: {mailbox}")
        server.select_folder(mailbox)
        
        # 未読メールのUID一覧を取得
        logger.debug("未読メール検索中...")
        uids = server.search(['UNSEEN'])
        logger.debug(f"未読メール数: {len(uids)}")
        
        if not uids:
            logger.info("未読メールなし - 処理スキップ")
            return

        logger.debug(f"メール取得開始: {len(uids)}件")
        fetch_start = time.time()
        messages = server.fetch(uids, ['RFC822'])
        logger.debug(f"メール取得完了: 所要時間={time.time() - fetch_start:.2f}秒")
        
        processed_uids = []
        
        # 非同期処理用のスレッドプール
        logger.debug("スレッドプール作成")
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            
            for uid, data in messages.items():
                uid_str = str(uid)
                logger.debug(f"メール処理: UID={uid_str}")
                
                # 処理済みかどうかをチェック
                already_processed = is_processed(db_conn, uid_str)
                
                # 未処理の場合のみn8nへ転送
                if not already_processed:
                    parse_start = time.time()
                    msg = email.message_from_bytes(data[b'RFC822'])
                    subject, body = process_email_content(msg)
                    logger.debug(f"メール解析完了: UID={uid_str}, 所要時間={time.time() - parse_start:.2f}秒")

                    # 非同期でn8nへ転送処理を実行
                    logger.debug(f"非同期タスク投入: UID={uid_str}")
                    futures.append(executor.submit(forward_to_n8n, n8n_webhook_url, subject, body))
                    
                    # 処理済みとしてマーク
                    db_start = time.time()
                    mark_processed(db_conn, uid_str)
                    logger.debug(f"DB処理完了: UID={uid_str}, 所要時間={time.time() - db_start:.2f}秒")
                else:
                    logger.debug(f"UID={uid_str} は既に処理済み - 転送をスキップ")
                
                # 処理済み・未処理に関わらず、すべてのメールをprocessedフォルダにコピー
                processed_uids.append(uid)
            
            # すべてのメールをprocessedフォルダにコピー（一括処理）
            if processed_uids and config.get('archive_mails', True):
                logger.debug(f"メールをprocessedフォルダにコピーします: {len(processed_uids)}件")
                try:
                    server.copy(processed_uids, "processed")
                    server.delete_messages(processed_uids)
                    server.expunge()
                    logger.info(f"メールを処理完了・削除しました: {len(processed_uids)}件")
                except Exception as e:
                    logger.error(f"メールのフォルダ移動中にエラー: {e}")
            
            # 完了を待つ（エラーハンドリング用）
            logger.debug(f"全タスク投入完了: {len(futures)}件, 完了待ち...")
            for future in concurrent.futures.as_completed(futures):
                try:
                    future.result()  # エラーチェック
                except Exception as e:
                    logger.error(f"非同期通知処理でエラー: {e}")
                    logger.error(f"例外詳細: {traceback.format_exc()}")

        # 既読フラグをつける
        if uids:
            flag_start = time.time()
            server.add_flags(uids, ['\\Seen'])
            logger.debug(f"既読フラグ設定完了: 所要時間={time.time() - flag_start:.2f}秒")
            logger.info(f"{len(uids)}件のメールを処理完了")
    except Exception as e:
        logger.error(f"fetch_and_forward処理エラー: {e}")
        logger.error(f"例外詳細: {traceback.format_exc()}")
    finally:
        logger.debug(f"=== fetch_and_forward終了: 合計所要時間={time.time() - start_time:.2f}秒 ===")

def run_idle_session(server, db_conn, n8n_webhook_url, mailbox="INBOX"):
    """
    IMAP IDLEで待機し、変化があったらfetch_and_forwardを呼び出す。
    タイムアウト時は特定の間隔でのみチェックする。
    """
    start_time = time.time()
    logger.info("IMAP IDLE待機中...")
    try:
        logger.debug("IDLE開始")
        server.idle()
        # タイムアウト値を30秒に設定
        logger.debug("IDLE_check開始（タイムアウト=30秒）")
        responses = server.idle_check(timeout=30)
        logger.debug(f"IDLE_check完了: 応答={responses}")
        server.idle_done()
        logger.debug("IDLE終了")
        
        if responses:
            logger.info("新着メールの通知を受けた => fetch_and_forward実行")
            fetch_and_forward(server, db_conn, n8n_webhook_url, mailbox)
        else:
            # タイムアウト時は何もしない（定期的なチェックは別途実施）
            logger.info("IDLEタイムアウト(30秒)")
            
        logger.info("IDLE処理サイクル完了")
        logger.debug(f"IDLE処理サイクル所要時間: {time.time() - start_time:.2f}秒")
        return True
    except Exception as e:
        logger.error(f"IDLE中エラー: {e}")
        logger.error(f"例外詳細: {traceback.format_exc()}")
        return False

def reconnect_loop(db_conn, n8n_webhook_url, host, port, username, password, mailbox="INBOX"):
    """
    接続が切れたらリトライし続けるループ。
    定期的に再接続も行う。
    """
    context = ssl.create_default_context()
    # 必要に応じて古いSSL/TLSを許可したい場合
    context.options |= ssl.OP_LEGACY_SERVER_CONNECT
    
    # 接続関連の定数
    MAX_SESSION_TIME = 600  # 10分ごとに強制再接続
    MAX_IDLE_CYCLES = 20    # または20回のIDLEサイクル後に再接続
    PERIODIC_CHECK_INTERVAL = 5  # 5サイクルに1回は全メール確認
    
    while True:
        try:
            with IMAPClient(host, port=port, ssl=True, ssl_context=context) as server:
                logger.info("IMAPサーバにログイン...")
                server.login(username, password)
                server.select_folder(mailbox)
                
                session_start = time.time()
                idle_cycles = 0
                
                # 内部ループ - 一定時間または一定サイクル数で抜ける
                while (time.time() - session_start < MAX_SESSION_TIME) and (idle_cycles < MAX_IDLE_CYCLES):
                    if run_idle_session(server, db_conn, n8n_webhook_url, mailbox):
                        idle_cycles += 1
                        
                        # 定期的にメールチェックを実行（応答が無い場合のバックアップ）
                        if idle_cycles % PERIODIC_CHECK_INTERVAL == 0:
                            logger.info(f"定期チェック（{PERIODIC_CHECK_INTERVAL}サイクル毎） => fetch_and_forward実行")
                            fetch_and_forward(server, db_conn, n8n_webhook_url, mailbox)
                    else:
                        # エラーが発生した場合は内部ループを抜ける
                        break
                
                logger.info(f"セッション再接続（経過時間: {int(time.time() - session_start)}秒, IDLE回数: {idle_cycles}回）")
                # with文を抜けることでIMAPClientが自動的にlogoutされる
                
        except Exception as e:
            logger.error(f"IMAP接続エラー。5秒後リトライ: {e}")
            time.sleep(5)

def main():
    # 1) DB初期化
    db_conn = init_db()

    # 2) IMAPの接続情報
    #    (本来はYAML/ENVなどから読み込んでください)
    host = os.environ.get("IMAP_HOST", "imap.spmode.ne.jp")
    port = int(os.environ.get("IMAP_PORT", 993))
    username = os.environ.get("IMAP_USER", "")
    password = os.environ.get("IMAP_PASSWORD", "")
    mailbox = os.environ.get("IMAP_MAILBOX", "INBOX")

    # 3) n8n Webhook URL
    #    (本来は環境変数 or configファイルから読み込んでください)
    n8n_webhook_url = os.environ.get("N8N_WEBHOOK_URL", "https://{N8N_HOST}/webhook/XXXXX")

    logger.info("IMAP -> n8n転送スクリプト開始")
    logger.info(f"host={host}, port={port}, user={username}, mailbox={mailbox}")
    logger.info(f"n8n URL={n8n_webhook_url}")

    try:
        reconnect_loop(db_conn, n8n_webhook_url, host, port, username, password, mailbox)
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt: 終了します。")
        sys.exit(0)

if __name__ == "__main__":
    main()
