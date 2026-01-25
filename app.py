"""
Demo app with SQL injection vulnerabilities.
Fixpoint will automatically detect and fix these!
"""
import sqlite3


def get_database_connection():
    """Get database connection."""
    return sqlite3.connect("users.db")


def get_user_by_email(email):
    """
    VULNERABLE: SQL Injection via f-string
    
    An attacker could input: ' OR '1'='1
    This would return all users!
    """
    conn = get_database_connection()
    cursor = conn.cursor()
    
    # VULNERABLE - f-string SQL injection
    query = f"SELECT * FROM users WHERE email = '{email}'"
    cursor.execute(query)
    
    return cursor.fetchone()


def get_user_by_id(user_id):
    """
    VULNERABLE: SQL Injection via string concatenation
    """
    conn = get_database_connection()
    cursor = conn.cursor()
    
    # VULNERABLE - string concatenation
    sql = "SELECT * FROM users WHERE id = " + str(user_id)
    cursor.execute(sql)
    
    return cursor.fetchone()


def search_users(search_term):
    """
    VULNERABLE: SQL Injection via .format()
    """
    conn = get_database_connection()
    cursor = conn.cursor()
    
    # VULNERABLE - .format() SQL injection
    query = "SELECT * FROM users WHERE name LIKE '%{}%'".format(search_term)
    cursor.execute(query)
    
    return cursor.fetchall()


def get_orders_by_status(status):
    """
    VULNERABLE: SQL Injection via % formatting
    """
    conn = get_database_connection()
    cursor = conn.cursor()
    
    # VULNERABLE - % formatting SQL injection
    stmt = "SELECT * FROM orders WHERE status = '%s'" % status
    cursor.execute(stmt)
    
    return cursor.fetchall()


# This one is SAFE - Fixpoint will skip it
def get_user_safe(email):
    """
    SAFE: Already using parameterized query
    """
    conn = get_database_connection()
    cursor = conn.cursor()
    
    query = "SELECT * FROM users WHERE email = %s"
    cursor.execute(query, (email,))
    
    return cursor.fetchone()


if __name__ == "__main__":
    # Demo usage
    print("Fetching user by email...")
    user = get_user_by_email("test@example.com")
    print(f"User: {user}")
