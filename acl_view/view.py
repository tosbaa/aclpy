import subprocess
import re
import sys
import json
import os

FILE_PATH = sys.argv[2]
PERMISSIONS_PATTERN = "%s([wrx-]{3}).*([wrx-]{3})|%s([wrx-]{3}).*([wrx-]{3})*"
FILE_OWNER_GROUP = {"file" : "# file: ", "owner" : "# owner: " , "group" : "# group: "}
PERMISSIONS_GROUP = {"user_permission" : "user::", "group_permission" : "group::", "other_permission" : "other::"}
USERS_GROUPS_PATTERN = "%s:([wrx-]{3}).*([wrx-]{3})|%s:([wrx-]{3}).*([wrx-]{3})*" 

def get_acl(file_path):
    bash_script = "getfacl {:s}".format(file_path)
    bash_output = subprocess.Popen(bash_script, shell=True, stdout=subprocess.PIPE).stdout
    acl_string = bash_output.read().decode("utf-8")
    return acl_string

def parse_acl(acl_string):
    acl_dict = {}

    for key, key_pattern in FILE_OWNER_GROUP.items():
        acl_dict[key] = re.search("%s(.*)" % (key_pattern), acl_string).group(1)
    
    for key, key_pattern in PERMISSIONS_GROUP.items():
        match_group = re.search(PERMISSIONS_PATTERN % (key_pattern, key_pattern), acl_string).groups()
        acl_dict[key] = list(filter(lambda match: match != None, match_group))

    users = re.findall("user:([\w\d]+)", acl_string)
    groups = re.findall("group:([\w\d]+)", acl_string)
    
    user_list = []
    group_list = []

    for user in users:
        match_group = re.search(USERS_GROUPS_PATTERN % (user, user), acl_string).groups()
        match_group_valid = list(filter(lambda match: match != None, match_group))
        user_list.append({user : match_group_valid})
        acl_dict["users"] = user_list

    for group in groups:
        match_group = re.search(USERS_GROUPS_PATTERN % (group, group), acl_string).groups()
        match_group_valid = list(filter(lambda match: match != None, match_group))
        group_list.append({group : match_group_valid})
        acl_dict["groups"] = group_list
    


    for role in ["user", "group", "other"]:
        default_permissions = re.search("default:%s::(.*)" % role, acl_string)
        if default_permissions is not None:
            acl_dict["default_%s" % role] = default_permissions.group(1) 

    mask_match = re.search("mask::(.*)", acl_string)
    if mask_match is not None:
        acl_dict["mask"] = mask_match.group(1)

    default_users = re.findall("default:user:([\d\w]+):", acl_string)
    default_groups = re.findall("default:group:([\d\w]+):", acl_string)

    default_users_list = []
    default_groups_list = []

    for default_user in default_users:
        default_user_permission = re.search("default:user:%s:([wrx-]+)" % default_user, acl_string)
        if default_user_permission is not None:
            default_users_list.append({default_user : default_user_permission.group(1)})        
    if default_users:
        acl_dict["default_users"] = default_users_list 

    for default_group in default_groups:
        default_group_permission = re.search("default:group:%s:([wrx-]+)" % default_group, acl_string)
        if default_group_permission is not None:
            default_groups_list.append({default_group : default_group_permission.group(1)})
    if default_groups:
        acl_dict["default_groups"] = default_groups_list
    return json.dumps(acl_dict)

def before():
    if not os.path.exists(FILE_PATH):
        print("Given path is not exist")
        exit()

def run():
    print(parse_acl(get_acl(FILE_PATH)))

def after():
    print("ok")

    
def automate():
    before()
    run()
    after()

if __name__ == "__main__":
   globals()[sys.argv[1]]()

