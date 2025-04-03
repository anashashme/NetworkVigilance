import subprocess
from database.db import get_db_connection

def block_ip(ip):
    """
    Block an IP address by creating a firewall rule and logging it once.
    Prevents duplicate rules and relies on DB UNIQUE constraint for src_ip.
    """
    try:
        rule_name = f"Block_{ip}"

        # Check if the firewall rule already exists
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "show", "rule", f"name={rule_name}"],
            capture_output=True,
            text=True,
            shell=True
        )

        if "No rules match" not in result.stdout:
            print(f"[SKIP] Firewall rule for {ip} already exists.")
        else:
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule",
                 f"name={rule_name}",
                 "dir=in",
                 "action=block",
                 f"remoteip={ip}",
                 "enable=yes"],
                shell=True
            )
            print(f"[OK] Firewall rule added for {ip}.")

        # Insert into DB only if not already exists
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO blocked_ips (src_ip, timestamp)
            VALUES (%s, NOW())
            ON CONFLICT (src_ip) DO NOTHING;
            """,
            (ip,)
        )
        conn.commit()
        cur.close()
        conn.close()

        print(f"[OK] IP {ip} logged to blocked_ips table.")

    except Exception as e:
        print(f"[ERROR] Block IP {ip}: {str(e)}")


def unblock_firewall_rule(ip):
    """
    Remove all firewall rules with the given IP's rule name.
    Handles duplicates by looping until no rules remain.
    """
    rule_name = f"Block_{ip}"
    removed = False

    while True:
        result = subprocess.run(
            ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
            capture_output=True,
            text=True,
            shell=True
        )

        if "No rules match" in result.stdout:
            break
        else:
            removed = True
            print(f"[INFO] Removed one rule for IP: {ip}")

    if removed:
        print(f"[CLEAN] All rules removed for IP: {ip}")
    else:
        print(f"[SKIP] No rules found for IP: {ip}")


def unblock_ip(ip):
    """
    Unblock an IP by deleting all its firewall rules and removing it from the database.
    """
    try:
        unblock_firewall_rule(ip)

        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("DELETE FROM blocked_ips WHERE src_ip = %s", (ip,))
        conn.commit()
        cur.close()
        conn.close()

        print(f"[OK] Unblocked IP: {ip}")

    except Exception as e:
        print(f"[ERROR] Unblocking IP {ip}: {str(e)}")


def unblock_ip_by_id(ip_id):
    """
    Unblock a specific IP based on its database ID.
    """
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT src_ip FROM blocked_ips WHERE id = %s", (ip_id,))
        row = cur.fetchone()
        cur.close()
        conn.close()

        if row:
            ip = row[0]
            unblock_ip(ip)
        else:
            print(f"[WARN] No IP found with ID {ip_id}")

    except Exception as e:
        print(f"[ERROR] Unblock by ID {ip_id}: {str(e)}")
