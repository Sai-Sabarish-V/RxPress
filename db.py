from typing import Any, Dict, Iterable, List, Optional, Tuple

import os
import mysql.connector
from mysql.connector import MySQLConnection

from config import get_database_config


def get_connection() -> MySQLConnection:
    cfg = get_database_config()
    connect_args = {
        "host": cfg["host"],
        "user": cfg["user"],
        "password": cfg["password"],
        "database": cfg["database"],
        "connection_timeout": 10,
        "autocommit": True,
    }
    # Optionally include port and SSL CA if provided
    if "port" in cfg and cfg["port"]:
        connect_args["port"] = cfg["port"]
    ssl_ca = cfg.get("ssl_ca")
    if ssl_ca and os.path.exists(ssl_ca):
        connect_args.update({
            "ssl_ca": ssl_ca,
            "ssl_verify_cert": True,
        })
    conn: MySQLConnection = mysql.connector.connect(**connect_args)
    return conn


def fetch_all(query: str, params: Optional[Iterable[Any]] = None) -> List[Dict[str, Any]]:
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query, params or [])
        rows = cursor.fetchall()
        return rows
    finally:
        conn.close()


def fetch_one(query: str, params: Optional[Iterable[Any]] = None) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query, params or [])
        row = cursor.fetchone()
        return row
    finally:
        conn.close()


def execute(query: str, params: Optional[Iterable[Any]] = None) -> int:
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(query, params or [])
        conn.commit()
        return cursor.rowcount
    finally:
        conn.close()


def execute_returning_id(query: str, params: Optional[Iterable[Any]] = None) -> int:
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(query, params or [])
        last_id = cursor.lastrowid
        conn.commit()
        return last_id
    finally:
        conn.close()


def table_exists(table_name: str) -> bool:
    row = fetch_one(
        """
        SELECT 1 AS exists_flag
        FROM information_schema.tables
        WHERE table_schema = DATABASE() AND table_name = %s
        LIMIT 1
        """,
        [table_name],
    )
    return bool(row)


def column_exists(table_name: str, column_name: str) -> bool:
    row = fetch_one(
        """
        SELECT 1 AS exists_flag
        FROM information_schema.columns
        WHERE table_schema = DATABASE() AND table_name = %s AND column_name = %s
        LIMIT 1
        """,
        [table_name, column_name],
    )
    return bool(row)
