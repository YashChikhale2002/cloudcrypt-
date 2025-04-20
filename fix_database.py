#!/usr/bin/env python
"""
Fix datetime formats in Crypt+ database
"""
import os
import sys
import sqlite3
from datetime import datetime

# Add the current directory to the path so we can import our modules
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

# Import config
from config import Config

def fix_database_datetimes():
    """Fix all datetime fields in the database to be compatible with SQLAlchemy."""
    
    # Extract database path from Config
    db_path = Config.SQLALCHEMY_DATABASE_URI.replace('sqlite:///', '')
    
    print(f"Connecting to database: {db_path}")
    
    # Connect to the database
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get all tables in the database
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = cursor.fetchall()
    
    for table in tables:
        table_name = table[0]
        print(f"\nChecking table: {table_name}")
        
        # Get column info for this table
        cursor.execute(f"PRAGMA table_info({table_name})")
        columns = cursor.fetchall()
        
        # Find all columns that might be datetime fields
        date_columns = []
        for col in columns:
            col_name = col[1]
            # Look for columns with names that suggest they are datetime fields
            if any(date_term in col_name.lower() for date_term in ['date', 'time', 'created', 'updated', 'timestamp']):
                date_columns.append(col_name)
        
        if not date_columns:
            print(f"  No potential datetime columns found in {table_name}")
            continue
            
        print(f"  Potential datetime columns found: {', '.join(date_columns)}")
        
        # Fix each potential datetime column
        for col_name in date_columns:
            try:
                # Get all values for this column
                cursor.execute(f"SELECT id, {col_name} FROM {table_name} WHERE {col_name} IS NOT NULL")
                rows = cursor.fetchall()
                
                fixed_count = 0
                for row in rows:
                    row_id = row[0]
                    date_value = row[1]
                    
                    # Skip if already in the correct format
                    if not date_value or ' ' in date_value:
                        continue
                    
                    # Look for problematic format with T and microseconds
                    if 'T' in date_value and '.' in date_value:
                        try:
                            # Parse the ISO format with microseconds
                            dt_parts = date_value.replace('T', ' ').split('.')
                            fixed_dt = dt_parts[0]  # Just take the part before the microseconds
                            
                            # Update the record
                            cursor.execute(f"UPDATE {table_name} SET {col_name} = ? WHERE id = ?", 
                                         (fixed_dt, row_id))
                            fixed_count += 1
                            print(f"    Fixed {col_name} format for {table_name} ID {row_id}: {date_value} -> {fixed_dt}")
                        except Exception as e:
                            print(f"    Error fixing {col_name} for {table_name} ID {row_id}: {str(e)}")
                
                if fixed_count > 0:
                    print(f"  Fixed {fixed_count} records in {table_name}.{col_name}")
            except sqlite3.OperationalError as e:
                # This might happen if the column doesn't exist in this table
                print(f"  Error accessing {col_name} in {table_name}: {str(e)}")
    
    # Commit changes
    conn.commit()
    print("\nDatabase fixes committed successfully")
    
    # Close connection
    conn.close()

if __name__ == "__main__":
    fix_database_datetimes()