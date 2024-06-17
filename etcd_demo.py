import subprocess as sp
import hashlib
import shlex

ETCDCTL_API=3
HOST_1="172.16.238.100"
HOST_2="172.16.238.101"
HOST_3="172.16.238.102"
ENDPOINTS=f"{HOST_1}:2379,{HOST_2}:2379,{HOST_3}:2379"

# docker exec etcd-node1-1 /usr/local/bin/etcdctl --endpoints=$ENDPOINTS --write-out=table endpoint status
ETCDCTL_CMD = f"docker exec etcd-node1-1 /usr/local/bin/etcdctl --endpoints={ENDPOINTS}"
ROOT_NAME = 'root'
ROOT_PASSWORD = 'test'

def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def etcdctl_cmd(command, user=None, password=None):
    if user and password:
        command = f"--user {user}:{password} " + command
    cmd = f"{ETCDCTL_CMD} {command}"
    result = sp.run(shlex.split(cmd), capture_output=True, text=True)
    if result.returncode == 0:
        return result.stdout.strip()
    else:
        print(f"Error in {command}: {result.stderr}")
        return None

def etcdctl_put(key, value, user=None, password=None):
    return etcdctl_cmd(f"put {key} {value}", user, password)

def etcdctl_get(key, user=None, password=None):
    return etcdctl_cmd(f"get {key} --print-value-only", user, password)

def etcdctl_user_add(username, password, user=None, password_admin=None):
    return etcdctl_cmd(f"user add {username}:{password}", user, password_admin)

def etcdctl_role_add(role, user=None, password=None):
    existing_roles = etcdctl_cmd(f"role list", user, password).split()
    if role in existing_roles:
        return None
    return etcdctl_cmd(f"role add {role}", user, password)

def etcdctl_grant_permission(role, permission_type, key, user=None, password=None):
    return etcdctl_cmd(f"role grant-permission {role} {permission_type} {key}", user, password)

def etcdctl_grant_role(username, role, user=None, password=None):
    return etcdctl_cmd(f"user grant-role {username} {role}", user, password)

def etcdctl_revoke_role(username, role, user=None, password=None):
    user_roles = etcdctl_cmd(f"user get {username}", user, password).split()
    if role not in user_roles:
        return None
    return etcdctl_cmd(f"user revoke-role {username} {role}", user, password)

def register(username, password):
    hashed_password = hash_password(password)
    user_key = f'/users/{username}'
    
    if etcdctl_get(user_key, ROOT_NAME, ROOT_PASSWORD):
        print("Username already exists.")
        return False
    
    etcdctl_put(user_key, hashed_password, ROOT_NAME, ROOT_PASSWORD)
    
    etcdctl_user_add(username, password, ROOT_NAME, ROOT_PASSWORD)
    
    if not etcdctl_role_add("role-0", ROOT_NAME, ROOT_PASSWORD):
        etcdctl_grant_permission("role-0", "readwrite", "/config", ROOT_NAME, ROOT_PASSWORD)
    if not etcdctl_role_add("role-1", ROOT_NAME, ROOT_PASSWORD):
        etcdctl_grant_permission("role-1", "readwrite", "/config", ROOT_NAME, ROOT_PASSWORD)
    if not etcdctl_role_add("role-2", ROOT_NAME, ROOT_PASSWORD):
        etcdctl_grant_permission("role-2", "read", "/config", ROOT_NAME, ROOT_PASSWORD)
    
    etcdctl_grant_role(username, "role-2", ROOT_NAME, ROOT_PASSWORD)
    
    return True

def login(username, password):
    hashed_password = hash_password(password)
    user_key = f'/users/{username}'
    
    stored_password = etcdctl_get(user_key, ROOT_NAME, ROOT_PASSWORD)
    
    if not stored_password:
        print("Username not found.")
        return False
    
    if stored_password == hashed_password:
        print("Login successful.")
        return True
    else:
        print("Incorrect password.")
        return False

def query_config(username, password):
    value = etcdctl_get('/config', username, password)
    if value is not None:
        print(f"Current config value: {value}")
    else:
        print("Config not found.")

def modify_config(username, password):
    roles = etcdctl_cmd(f"user get {username}", username, password)
    if 'role-0' not in roles and 'role-1' not in roles:
        print("Permission denied: You do not have permission to modify config.")
        return

    new_value = input("Enter new config value: ").strip()
    etcdctl_put('/config', new_value, username, password)
    print("Config updated.")

def adjust_user_role():
    target_user = input("Enter the username to adjust the role: ").strip()
    new_role = input("Enter the new role (0: root, 1: admin, 2: read-only): ").strip()

    if new_role == '0':
        role = 'role-0'
    elif new_role == '1':
        role = 'role-1'
    elif new_role == '2':
        role = 'role-2'
    else:
        print("Invalid role.")
        return
    
    etcdctl_revoke_role(target_user, "role-0", ROOT_NAME, ROOT_PASSWORD)
    etcdctl_revoke_role(target_user, "role-1", ROOT_NAME, ROOT_PASSWORD)
    etcdctl_revoke_role(target_user, "role-2", ROOT_NAME, ROOT_PASSWORD)
    
    etcdctl_grant_role(target_user, role, ROOT_NAME, ROOT_PASSWORD)
    print(f"User {target_user} role updated to {role}.")

def user_menu(username, password):
    while True:
        print("1. Query config")
        if 'role-0' in etcdctl_cmd(f"user get {username}", username, password) or 'role-1' in etcdctl_cmd(f"user get {username}", username, password):
            print("2. Modify config")
        if username == ROOT_NAME:
            print("3. Adjust user roles")
            print("4. Logout")
        else:
            print("3. Logout")
        choice = input("Choose an option: ").strip()
        
        if choice == '1':
            query_config(username, password)
        elif choice == '2' and ('role-0' in etcdctl_cmd(f"user get {username}", username, password) or 'role-1' in etcdctl_cmd(f"user get {username}", username, password)):
            modify_config(username, password)
        elif choice == '3' and username == ROOT_NAME:
            adjust_user_role()
        elif choice == '4' and username == ROOT_NAME:
            break
        elif choice == '3' and username != ROOT_NAME:
            break
        else:
            print("Invalid choice. Please choose again.")

if __name__ == "__main__":
    while True:
        action = input("Choose action: [register/login/exit]: ").strip().lower()
        if action == 'exit':
            break
        username = input("Username: ").strip()
        password = input("Password: ").strip()
        
        if action == 'register':
            register(username, password)
        elif action == 'login':
            if login(username, password):
                user_menu(username, password)
        else:
            print("Invalid action. Please choose 'register', 'login', or 'exit'.")
