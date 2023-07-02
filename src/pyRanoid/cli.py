import utils as utils
import pyfiglet
from InquirerPy import prompt
from InquirerPy.validator import PathValidator
import sys
from termcolor import colored


print("\------------------------------------------------------------------------------------------------")
print(pyfiglet.figlet_format("pyRanoid")+"\n")
print(colored("(github.com/omnone/pyRanoid)", "cyan"))
print("\------------------------------------------------------------------------------------------------")

questions = [
    {
        "type": "list",
        "name": "op",
        "message": "Select an operation:",
        "choices": ["Encrypt to an image", "Decrypt from an image", "Quit"],
    },
    {
        "type": "input",
        "name": "image_path",
        "message": "Enter image path:",
        "validate": PathValidator("Path is not valid"),
        "when": lambda user_input: user_input["op"] != "Quit"

    },
    {
        "type": "input",
        "name": "target_path",
        "message": "Enter target path:",
        "validate": PathValidator("Path is not valid"),
        "when": lambda user_input: user_input["op"] != "Decrypt from an image" and
        user_input["op"] != "Quit"
    },
    {
        "type": "password",
        "name": "passw",
        "message": "Enter password:",
        "when": lambda user_input: user_input["op"] != "Quit"

    },
    {
        "type": "password",
        "name": "passw_verify",
        "message": "Reenter password:",
        "when": lambda user_input: user_input["op"] != "Quit"

    }

]

user_input = prompt(questions)

if user_input["op"] == "Encrypt to an image":

    if user_input["passw"] == user_input["passw_verify"]:
        utils.encrypt_image(
            user_input["image_path"], user_input["target_path"],
            password=user_input["passw"])
    else:
        print("Passwords dont match")


elif user_input["op"] == "Decrypt from an image":

    decrypted_msg = utils.decrypt_image(
        user_input["image_path"], password=user_input["passw"])

else:
    sys.exit(0)
