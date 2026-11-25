from app.db import close_db_connection, get_db_connection


def test_connection():
    connection = None
    cursor = None

    try:
        print("Connecting to PKI database...")

        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute("SELECT DATABASE(), VERSION();")
        database_name, mysql_version = cursor.fetchone()

        cursor.execute(
            """
            SELECT COUNT(*)
            FROM information_schema.tables
            WHERE table_schema = %s
            """,
            (database_name,),
        )

        table_count = cursor.fetchone()[0]

        print("Connection: OK")
        print(f"Database: {database_name}")
        print(f"MySQL Version: {mysql_version}")
        print(f"PKI Tables Found: {table_count}")

        if table_count != 5:
            raise RuntimeError(
                f"Expected 5 PKI tables but found {table_count}."
            )

        print("Database schema: OK")
        print("STEP 2 DATABASE TEST: PASSED")

    except Exception as exc:
        print("STEP 2 DATABASE TEST: FAILED")
        print(f"Reason: {exc}")
        raise

    finally:
        if cursor is not None:
            cursor.close()

        if connection is not None:
            close_db_connection(connection)


if __name__ == "__main__":
    test_connection()