# -*- coding: utf-8 -*-
import sqlite3


def check_con_db(database):
    '''Method to check the connection with our '''
    try:
        conn = sqlite3.connect(database)
        cur = conn.cursor()
        print("Base de données créee et correctement connectée à SQLite")

        sql = "SELECT sqlite_version();"
        cur.execute(sql)
        res = cur.fetchall()
        print("La version de SQLite est: ", res)
        cur.close()
        conn.close()
        print("La connexion SQLite est fermée")

    except sqlite3.Error as error:
        print("Erreur lors de la connexion à SQLite", error)


def print_db(database, table):
    try:
        sqliteConnection = sqlite3.connect(database)
        cursor = sqliteConnection.cursor()
        # print("Connected to SQLite")

        sqlite_select_query = "SELECT  * from " + table + " ;"
        cursor.execute(sqlite_select_query)
        res = cursor.fetchall()
        print("Total rows are:  ", len(res))
        print("Printing each row")
        if table == 'Logs':
            for row in res:
                print("ID: ", row[0], " Type: ", row[1], "  Protocol: ", row[2], "   MAC: ", row[3], "    IP_SRC: ",
                      row[4], "IP_DST: ", row[5])
                print("Content: ", row[6])
                print("Time: ", row[7], "Country: ", row[8], "\n")
        elif table == 'UnauthorizedDNSDHCP':
            for row in res:
                print("MAC address: ", row[0])
            print("")
        cursor.close()

    except sqlite3.Error as error:
        print("Failed to read data from sqlite table", error)
    finally:
        if (sqliteConnection):
            sqliteConnection.close()
            # print("The SQLite connection is closed")
        return res


def get_db(database, table):
    try:
        sqliteConnection = sqlite3.connect(database)
        cursor = sqliteConnection.cursor()
        # print("Connected to SQLite")

        sqlite_select_query = "SELECT  * from " + table + " ;"
        cursor.execute(sqlite_select_query)
        res = cursor.fetchall()
        cursor.close()

    except sqlite3.Error as error:
        print("Failed to read data from sqlite table", error)
    finally:
        if (sqliteConnection):
            sqliteConnection.close()
            # print("The SQLite connection is closed")
        return res


def sorted_print_db(database, table, sorted_elt, decreasing=False):
    desc = ""
    if decreasing:
        des = "DESC"
    try:
        conn = sqlite3.connect(database)
        cur = conn.cursor()
        cur.execute("SELECT * FROM " + table + " ORDER BY " + sorted_elt + " " + desc + " ;")
        conn.commit()
        res = cur.fetchall()

        if table == 'Logs':
            for row in res:
                print("ID: ", row[0], " Type: ", row[1], "  Protocol: ", row[2], "   MAC: ", row[3], "    IP_SRC: ",
                      row[4], "IP_DST: ", row[5])
                print("Content: ", row[6])
                print("Time: ", row[7], "Country: ", row[8], "\n")
        elif table == 'UnauthorizedDNSDHCP':
            for row in res:
                print("MAC address: ", row[0])
            print("")
        cur.close()

        print("Recherche réussie", res)

        cur.close()
        conn.close()
    except sqlite3.Error as error:
        print("Erreur lors de l'affichage", error)


def insert_db(database, table, elt):
    try:
        conn = sqlite3.connect(database)
        cur = conn.cursor()
        if table == 'Logs':
            cur.execute(
                "INSERT INTO Logs (TYPE,MAC,IP_SRC,IP_DST,CONTENT,COUNTRY,TIME,PROTOCOL) VALUES (?,?,?,?,?,?,?,?);",
                (elt[0], elt[1], elt[2], elt[3], elt[4], elt[5], elt[6], elt[7]))
            conn.commit()
        elif table == 'UnauthorizedDNSDHCP':
            cur.execute("INSERT INTO UnauthorizedDNSDHCP (MAC) VALUES " + elt + " ;")
            conn.commit()
        # print("Insertion réussie")
        cur.close()
        conn.close()

    except sqlite3.Error as error:
        print("Erreur lors de l'insertion", error)


def function_test():
    our_db = 'Dns_Dhcp.db'
    check_con_db(our_db)
    print_db(our_db, 'UnauthorizedDNSDHCP')
    element = ["DHCP", "8D:8D:DD:0F:16:1F", "121.195.118.141", "9.86.90.127", "Test", "Romania",
               "2017-01-01 10:20:05.123", "TCP"]
    insert_db(our_db, 'Logs', element)
    sorted_print_db(our_db,'Logs', 'MAC', True)


if __name__ == '__main__':
    # function_test()
    # select_db('Logs', 'MAC', '8c:f8:13:3b:43:5a')
    print()
