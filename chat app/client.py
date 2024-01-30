import socket
import threading
from tkinter import *
from tkinter import simpledialog, messagebox,PhotoImage, END
from datetime import datetime
import queue

should_exit = False
HOST = '127.0.0.1'
PORT = 5555
lock = threading.Lock()
img = None
signup_img = None


def create_main_gui(client_socket, username, message_queue):
    root = Tk()
    root.title("Instant Messaging")
    root.geometry('925x500+300+200')
    root.configure(bg="#85C1E9")  # Set background color to light blue

    my_message = StringVar()
    my_message.set("Type your message here...")
    def send_message():
        message = my_message.get().strip()
        if message:
            client_socket.send(message.encode('utf-8'))
            my_message.set("")
        else:
            messagebox.showwarning("Warning", "Please enter a non-empty message.")

    def change_username():
        new_username = simpledialog.askstring("Change Username", "Enter new username:")
        if new_username:
            client_socket.send(f"/change_username {new_username}".encode('utf-8'))
            update_displayed_username(new_username) 
        else:
            messagebox.showwarning("Warning", "Please enter a non-empty username.")
    
    def update_displayed_username(new_username):
        username_label.config(text=f"Username: {new_username}")

    def disconnect():
        global should_exit
        should_exit = True
        client_socket.send("/quit".encode('utf-8'))
        
        root.destroy()

    def receive_messages():
        global should_exit
        while not should_exit:
            try:
                message = client_socket.recv(1024).decode('utf-8')
                if not message:
                    break
                message_queue.put(message)
            except socket.error as e:
                print(f"Error receiving message: {e}")
                break


    def update_messages_listbox():
        while True:
            try:
                message = message_queue.get(block=False)
                timestamp = datetime.now().strftime("%m-%d %H:%M:%S")
                formatted_message = f"{message} [{timestamp}]"

                if message.startswith(username + ":"):
                    formatted_message = f"You{message[len(username):]} [{timestamp}]"

                messages_listbox.insert(END, formatted_message)
                messages_listbox.yview(END)
            except queue.Empty:
                break




            
      
    def show_user_list():
        client_socket.send("/get_user_list".encode('utf-8'))
    

    messages_listbox = Listbox(root, height=15, width=50, bg="#ECF0F1", fg="black", selectbackground="#A9A9A9", selectforeground="white")
    messages_listbox.pack(padx=10, pady=10, expand=True, fill="both", side="left")

    scrollbar = Scrollbar(root, command=messages_listbox.yview)
    scrollbar.pack(side="right", fill="y")

    messages_listbox.config(yscrollcommand=scrollbar.set)

    entry_field = Entry(root, textvariable=my_message, bg="white", fg="black", width=35)
    entry_field.bind("<Return>", lambda event=None: send_message())
    entry_field.pack(padx=10, pady=10, side="left")

    send_button = Button(root, text="Send", command=send_message, bg="#57a1f8", fg="white")
    send_button.pack(pady=5, padx=5, side="left")

    menu_bar = Menu(root, font=('Helvetica', 12))  # Increase font size for the menu options
    root.config(menu=menu_bar)

    options_menu = Menu(menu_bar, tearoff=0, font=('Helvetica', 12))  # Increase font size for the options
    menu_bar.add_cascade(label="Options", menu=options_menu)
    options_menu.add_command(label="Change Username", command=change_username)
    options_menu.add_command(label="Show User List", command=show_user_list)
    options_menu.add_command(label="Show Chat History",command=lambda:show_chat_history_window(messages_listbox, client_socket))
    options_menu.add_command(label="Disconnect", command=disconnect)

    username_label = Label(root, text=f"Username: {username}", bg="#fff", fg="#333333", font=('Helvetica', 12))
    username_label.pack(pady=5, side="bottom")

    receive_thread = threading.Thread(target=receive_messages)
    receive_thread.daemon = True
    receive_thread.start()

    def update_gui_after():
        update_messages_listbox()
        root.after(100, update_gui_after)


    root.after(100, update_gui_after)
    root.mainloop()



def signup(signup_window, new_username_entry, new_password_entry):
    new_username = new_username_entry.get()
    new_password = new_password_entry.get()

    if new_username and new_password:
        # Create a new thread to handle signup asynchronously
        signup_thread = threading.Thread(target=perform_signup, args=(signup_window, new_username, new_password))
        signup_thread.start()
    else:
        messagebox.showwarning("Warning", "Please enter a non-empty username and password.")

def perform_signup(signup_window, new_username, new_password):
    try:
        signup_data = f"/signup {new_username},{new_password}".encode('utf-8')
        client_socket.send(signup_data)

        # Receive the length of the response
        response_length_bytes = client_socket.recv(4)  # Assuming the length is sent as 4 bytes
        response_length = int.from_bytes(response_length_bytes, byteorder='big')

        # Receive the response in chunks until the entire message is received
        response = b''
        while len(response) < response_length:
            chunk = client_socket.recv(min(2048, response_length - len(response)))
            if not chunk:
                break
            response += chunk

        # Decode the response and show the message
        response = response.decode('utf-8')
        messagebox.showinfo("Sign Up", response)

        # Check if the signup window is still valid before destroying it
        if signup_window and not signup_window.winfo_ismapped():
            signup_window.destroy()

    except socket.error as e:
        print(f"Error during signup: {e}")
        messagebox.showerror("Error", "Error during signup.")
        
def handle_signup():
    global signup_img  # Ensure that img is a global variable
    signup_window = Tk()
    signup_window.title("Sign Up")
    signup_window.geometry('925x500+300+200')
    signup_window.configure(bg="#fff")
    signup_window.resizable(False, False)

    frame = Frame(signup_window, bg="white")
    frame.pack(padx=20, pady=20, fill="both", expand=True)

    

    Label(frame, text='Sign up', fg='#57a1f8', bg="white", font=('Microsoft YaHei UI Light', 23, 'bold')).grid(row=0, column=1, pady=(5, 20), sticky="w")

    new_username_entry = Entry(frame, width=25, fg='black', border=0, bg="white", font=('Microsoft YaHei UI Light', 11))
    new_username_entry.grid(row=1, column=1, pady=(0, 10), sticky="w")
    new_username_entry.insert(0, 'Username')

    Frame(frame, height=2, bg='black').grid(row=2, column=1, columnspan=2, pady=5, sticky="w")

    new_password_entry = Entry(frame, width=25, fg='black', border=0, bg="white", font=('Microsoft YaHei UI Light', 11), show='*')
    new_password_entry.grid(row=3, column=1, pady=(10, 20), sticky="w")
    new_password_entry.insert(0, 'Password')

    Frame(frame, height=2, bg='black').grid(row=4, column=1, columnspan=2, pady=5, sticky="w")

    def signup_wrapper():
        signup(signup_window, new_username_entry, new_password_entry)

    signup_button = Button(frame, width=39, pady=7, text='Sign up', bg='#57a1f8', fg='white', border=0, command=signup_wrapper)
    signup_button.grid(row=5, column=1, pady=(10, 5), sticky="w")

    signup_window.mainloop()



def authenticate(authentication_window, username_entry, password_entry):
    username = username_entry.get()
    password = password_entry.get()
    response = ""  # Initialize response here

    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((HOST, PORT))

        client_socket.send(username.encode('utf-8'))

        server_request = client_socket.recv(1024).decode('utf-8')

        if server_request == "Please enter your password:" and not password.startswith("/get_chat_history"):
            client_socket.send(password.encode('utf-8'))

            response = client_socket.recv(1024).decode('utf-8')

            if response == "Authentication successful":
                messagebox.showinfo("Authentication", "Authentication successful.")

                # Create a message queue for the main GUI
                message_queue = queue.Queue()

                authentication_window.destroy()
                create_main_gui(client_socket, username, message_queue)
            else:
                messagebox.showerror("Authentication Failed", response)
                client_socket.close()
        else:
            # For /get_chat_history, don't send the password
            if not password.startswith("/get_chat_history"):
                client_socket.send(password.encode('utf-8'))

            response = client_socket.recv(1024).decode('utf-8')

            if response == "Authentication successful":
                messagebox.showinfo("Authentication", "Authentication successful.")

                # Create a message queue for the main GUI
                message_queue = queue.Queue()

                authentication_window.destroy()
                create_main_gui(client_socket, username, message_queue)
            else:
                messagebox.showerror("Authentication Failed", response)
                client_socket.close()

    except socket.error as e:
        print(f"Error connecting or sending authentication request: {e}")
        messagebox.showerror("Error", "Error connecting or sending authentication request.")




def show_chat_history_window(messages_listbox, client_socket):
    def get_chat_history():
        try:
            # Request chat history from the server
            client_socket.send("/get_chat_history".encode('utf-8'))

            # Receive and display chat history
            chat_history = client_socket.recv(2048).decode('utf-8')
            messages = chat_history.split('\n')

            for message in messages:
                history_window.after(100, chat_history_listbox.insert, END, message)
        except Exception as e:
            print(f"Error getting chat history: {e}")

    # Create a flag to check if the chat history has been received
    chat_history_received = threading.Event()

    # Function to set the flag when chat history is received
    def on_chat_history_received():
        chat_history_received.set()

    history_window = Toplevel()
    history_window.title("Chat History")

    chat_history_label = Label(history_window, text="Chat History:")
    chat_history_label.pack()

    chat_history_listbox = Listbox(history_window, height=20, width=50)
    chat_history_listbox.pack()

    # Run get_chat_history in a separate thread to avoid blocking the GUI
    threading.Thread(target=get_chat_history, daemon=True).start()

    # Set the flag when chat history is received
    threading.Thread(target=on_chat_history_received, daemon=True).start()

    # Wait for the chat history to be received before closing the window
    history_window.protocol("WM_DELETE_WINDOW", lambda: chat_history_received.wait() or history_window.destroy())

    history_window.mainloop()





if __name__ == "__main__":
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((HOST, PORT))
     
    authentication_window = Tk()
    authentication_window.title("Authentication")
    authentication_window.geometry('925x500+300+200')
    authentication_window.configure(bg="#fff")
    authentication_window.resizable(False, False)

    # Créer le Frame principal
    main_frame = Frame(authentication_window, bg="white")
    main_frame.pack(padx=20, pady=20, fill="both", expand=True)

    # Ajouter l'image à gauche du formulaire
    img = PhotoImage(file='login.png')
    
    Label(main_frame, image=img, bg='white').grid(row=0, column=0, rowspan=4, padx=(0, 20))

    # Créer un Frame pour le formulaire
    form_frame = Frame(main_frame, bg="white")
    form_frame.grid(row=0, column=1)

    Label(form_frame, text='Sign in', fg='#57a1f8', bg="white", font=('Microsoft YaHei UI Light', 23, 'bold')).grid(row=0, column=0, pady=(5, 20), sticky="w")

    # Username entry
    username_entry = Entry(form_frame, width=25, fg='black', border=0, bg="white", font=('Microsoft YaHei UI Light', 11))
    username_entry.grid(row=1, column=0, pady=(0, 15), padx=10, sticky="w")
    username_entry.insert(0, 'Username')

    # Ligne horizontale sous le nom d'utilisateur
    Frame(form_frame, height=2, bg='black').grid(row=2, column=0, pady=5, sticky="we")

    # Password entry
    password_entry = Entry(form_frame, width=25, fg='black', border=0, bg="white", font=('Microsoft YaHei UI Light', 11), show='*')
    password_entry.grid(row=3, column=0, pady=(15, 20), padx=10, sticky="w")
    password_entry.insert(0, 'Password')

    # Ligne horizontale sous le mot de passe
    Frame(form_frame, height=2, bg='black').grid(row=4, column=0, pady=5, sticky="we")

    # Bouton de connexion
    Button(form_frame, width=39, pady=7, text='Sign in', bg='#57a1f8', fg='white', border=0,
           command=lambda: authenticate(authentication_window, username_entry, password_entry)).grid(row=5, column=0, pady=(10, 5), sticky="w")

    Label(form_frame, text="Don't have an account?", fg='black', bg='white', font=('Microsoft YaHei UI Light', 9)).grid(row=6, column=0, pady=(5, 10), sticky="w")

    Button(form_frame, width=6, text='Sign up', border=0, bg='white', cursor='hand2', fg='#57a1f8', command=handle_signup).grid(row=7, column=0, pady=(0, 10), sticky="w")



    authentication_window.mainloop()
