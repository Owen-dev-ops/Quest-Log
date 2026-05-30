# Helper 
from flask import g, session, redirect, url_for
from functools import wraps
import sqlite3


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def connect_to_db():
    if "db" not in g:
        g.db = sqlite3.connect("quest_log.db", isolation_level=None)
        g.db.row_factory = sqlite3.Row
    return