import subprocess
import re
import sys
import json

TEST_FILE_PATH = "../testFile"

def get_acl(file_path):
    bash_script = "getfacl {:s}".format(file_path)
    bash_output = subprocess.Popen(bash_script, shell=True, stdout=subprocess.PIPE).stdout
    acl_string = bash_output.read().decode("utf-8")
    #acl_parts = re.findall("user:([\w\d]+.*)", acl_string)
    return acl_string

def parse_acl(acl_string):
    acl_dict = {}
    acl_dict["file"] = re.search("# file: (.*)", acl_string).group(1)
    acl_dict["owner"] = re.search("# owner: (.*)", acl_string).group(1)
    acl_dict["group"] = re.search("# group: (.*)", acl_string).group(1)
    acl_dict["user_permission"] = re.search("user::([wrx-]{3}).*([wrx-]{3})|group::([wrx-]{3}).*([wrx-]{3})*", acl_string).groups()
    acl_dict["group_permission"] = re.search("group::([wrx-]{3}).*([wrx-]{3})|group::([wrx-]{3}).*([wrx-]{3})*", acl_string).groups()
    acl_dict["other_permission"] = re.search("other::([wrx-]{3}).*([wrx-]{3})|group::([wrx-]{3}).*([wrx-]{3})*", acl_string).groups()
    acl_dict["mask"] = re.search("mask::(.*)", acl_string).group(1)

    user_with_permission = re.findall("user:([\w\d]+.*)", acl_string)
    group_with_permission = re.findall("group:([\w\d]+.*)", acl_string)
    
    user_list = []
    group_list = []

    for user_permission in user_with_permission:
        if "effective" in user_permission:
            user, permission, effective = user_permission.split(":")
            user_list.append({user : [permission[:3], effective]})
        else:
            user, permission = user_permission.split(":")
            user_list.append({user : permission})
        acl_dict["users"] = user_list

    for group_permission in group_with_permission:
        if "effective" in group_permission:
            group, permission, effective= group_permission.split(":")
            group_list.append({group : [permission[:3], effective]})
        else:
            group, permission = group_permission.split(":")
            group_list.append({group : permission})
        acl_dict["groups"] = group_list

    
    return json.dumps(acl_dict)

print(parse_acl(get_acl(TEST_FILE_PATH)))
#effective()



    
