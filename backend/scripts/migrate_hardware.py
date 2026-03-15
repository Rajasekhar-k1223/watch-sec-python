import sqlite3
import os

# Path to database
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) # Go up from scripts/ to app/
DB_PATH = os.path.join(os.path.dirname(BASE_DIR), "watchsec.db") # Assuming root/watchsec.db

def migrate():
    print(f"Checking Database at: {DB_PATH}")
    if not os.path.exists(DB_PATH):
        print("Database not found. Skipping migration (will be created fresh).")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        print("Attempting to add column 'HardwareJson' to 'Agents' table...")
        cursor.execute("ALTER TABLE Agents ADD COLUMN HardwareJson TEXT")
        conn.commit()
        print("Success: Column 'HardwareJson' added.")
    except sqlite3.OperationalError as e:
        if "duplicate column" in str(e):
            print("Info: Column 'HardwareJson' already exists.")
        else:
            print(f"Error: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    migrate()
