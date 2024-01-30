import socket
import threading
import mysql.connector
from mysql.connector import Error

HOST = '127.0.0.1'
PORT = 5555
DB_HOST = 'localhost'
DB_USER = 'root'
DB_PASSWORD = 'ayoub2000@'
DB_NAME = 'application'

# Dictionary to store connected clients and their usernames
clients = {}
current_user_socket = None  # Variable to keep track of the current user's socket



def handle_client(client_socket, addr):
    current_user_socket= None  # Référence à la variable globale

    try:
        # Recevoir et définir le nom d'utilisateur
        username = client_socket.recv(1024).decode('utf-8')
        clients[client_socket] = username

        # Demander le mot de passe pour l'authentification
        client_socket.send("Please enter your password:".encode('utf-8'))

        # Recevoir et vérifier le mot de passe par rapport à la base de données
        password = client_socket.recv(1024).decode('utf-8')
        if authenticate_user(username, password):
            client_socket.send("Authentication successful".encode('utf-8'))

            # Mettre à jour le statut de l'utilisateur dans la base de données
            update_user_status(username, "Online")

            broadcast(f"{username} has joined the chat.")
            
            # Mettre à jour current_user_socket
            current_user_socket = client_socket
        else:
            client_socket.send("Authentication failed".encode('utf-8'))
            client_socket.close()
            del clients[client_socket]
            return

       
        current_user_socket = client_socket

        # Gérer les messages du client
        while True:
            message = client_socket.recv(1024).decode('utf-8')
            if message.startswith("/signup"):
                handle_signup(client_socket)
            elif message == "/quit":
                print(f"{username} has left the chat.")
                broadcast(f"{username} has left the chat.")
                # Mettre à jour le statut de l'utilisateur dans la base de données
                update_user_status(username, "Offline")
                del clients[client_socket]
                client_socket.close()
                break
            elif message == "/get_user_list":
                user_list = get_user_list()
                client_socket.send("\n".join(user_list).encode('utf-8'))
            elif message == "/get_chat_history":
                print(f"Received /get_chat_history request from {username}")
                chat_history = get_chat_history()
                print(f"Sending chat history to {username}")
                # Envoyer l'historique du chat à l'utilisateur sans demander le mot de passe
                client_socket.send(chat_history.encode('utf-8'))           
            elif message.startswith("/change_username"):
                new_username = message.split(" ")[1]
                update_username_in_database(username, new_username)
                broadcast(f"{username} has changed their username to {new_username}.")
                username = new_username    
            else:
                # Afficher "You: message" pour l'expéditeur et "username: message" pour les autres
                broadcast(f"{username}: {message}", include_sender=True, sender_socket=client_socket)
                insert_chat_message(username, message)

    except socket.error as e:
        print(f"Error handling client {addr}: {e}")
        del clients[client_socket]









def authenticate_user(username, password):
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        cursor = conn.cursor()

        # Check if the username and password match in the database
        cursor.execute("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
        result = cursor.fetchone()
 
        conn.close()
        print(f"Checking username existence for {username}: {result}")
        return result is not None
    except Error as e:
        print(f"Error authenticating user: {e}")
        return False

def broadcast(message, include_sender=False, sender_socket=None):
    for client_socket in clients:
        try:
            # Ajoutez cette condition pour inclure ou exclure l'expéditeur
            if include_sender or client_socket != sender_socket:
                client_socket.send(message.encode('utf-8'))
        except socket.error as e:
            print(f"Error broadcasting message: {e}")






def handle_signup(client_socket):
    try:
        # Receive and set the new username and password
        data = client_socket.recv(1024).decode('utf-8')
        print(f"Received signup data: {data}")
        new_username, new_password = data.split(',')
        
        # Check if the new username already exists
        print(f"Received new username: {new_username}")
        if not username_exists(new_username):
            # Add the new user to the database
            print(new_username, new_password)
            add_user_to_database(new_username, new_password)

            response = "Sign up successful"
        else:
            response = "Username already exists. Please choose a different username."
        response_length = len(response)
        client_socket.sendall(response_length.to_bytes(2048, byteorder='big'))  # Envoyer la longueur
        client_socket.sendall(response.encode('utf-8'))  # Envoyer le contenu
    except socket.error as e:
        print(f"Error handling sign-up request: {e}")




def username_exists(username):
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        cursor = conn.cursor()

        # Check if the username exists in the database
        cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
        result = cursor.fetchone()

        conn.close()
        print(f"Checking username existence for {username}: {result}")
        return result is not None

    except Error as e:
        print(f"Error checking username existence: {e}")
        return False

def add_user_to_database(username, password):
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        cursor = conn.cursor()

        # Insert the new user into the database
        cursor.execute("INSERT INTO users VALUES (%s, %s)", (username, password))
       

        conn.commit()
        conn.close()
        print(f"Added user to database: {username}")
    except Error as e:
        print(f"Error adding user to the database: {e}")


def update_user_status(username, status):
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        cursor = conn.cursor()

        # Mettez à jour le statut de l'utilisateur dans la base de données
        cursor.execute("UPDATE users SET status = %s WHERE username = %s", (status, username))

        conn.commit()
        conn.close()

    except Error as e:
        print(f"Error updating user status: {e}")



def get_user_list():
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        cursor = conn.cursor()

        # Sélectionnez tous les utilisateurs et leurs statuts depuis la base de données
        cursor.execute("SELECT username, status FROM users")
        user_list = cursor.fetchall()

        conn.close()

        # Formatez la liste d'utilisateurs pour l'envoi au client
        user_list_str = [f"{username}: {status} " for username, status in user_list]
        return user_list_str

    except Error as e:
        print(f"Error getting user list: {e}")
        return []


def get_chat_history():
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        cursor = conn.cursor()

        # Sélectionnez l'historique de chat depuis la base de données
        cursor.execute("SELECT username, message FROM chat_history ORDER BY timestamp")
        history = cursor.fetchall()

        conn.close()

        # Formatez l'historique de chat pour l'envoi au client
        chat_history_str = "\n".join([f"{username}: {message}" for username, message in history])
        return chat_history_str

    except Error as e:
        print(f"Error getting chat history: {e}")
        return "Error getting chat history."


def insert_chat_message(username, message):
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        cursor = conn.cursor()

        # Insérez le message dans la table chat_history
        cursor.execute("INSERT INTO chat_history (username, message) VALUES (%s, %s)", (username, message))
        conn.commit()

        conn.close()

    except Error as e:
        print(f"Error inserting chat message: {e}")





def update_username_in_database(old_username, new_username):
    try:
        conn = mysql.connector.connect(
            host=DB_HOST,
            user=DB_USER,
            password=DB_PASSWORD,
            database=DB_NAME
        )
        cursor = conn.cursor()

        # Mettez à jour le nom d'utilisateur dans la table des utilisateurs
        cursor.execute("UPDATE users SET username = %s WHERE username = %s", (new_username, old_username))

        # Mettez à jour le nom d'utilisateur dans la table de l'historique du chat
        cursor.execute("UPDATE chat_history SET username = %s WHERE username = %s", (new_username, old_username))

        conn.commit()
        conn.close()

    except Error as e:
        print(f"Error updating username in the database: {e}")




def start_server():
    

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((HOST, PORT))
    server_socket.listen()

    print(f"Server listening on {HOST}:{PORT}")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"Accepted connection from {addr}")

        client_thread = threading.Thread(target=handle_client, args=(client_socket, addr))
        client_thread.start()

if __name__ == "__main__":
    start_server()