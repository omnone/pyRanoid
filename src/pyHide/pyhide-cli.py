import lsbSteg
import pyfiglet
from PyInquirer import prompt
from os import path
from prompt_toolkit.validation import Validator, ValidationError
import sys
from termcolor import colored


class PathValidator(Validator):
    def validate(self, document):
        imgPath = path.exists(document.text)
        if not imgPath:
            raise ValidationError(
                message='[-]Please enter a valid file path',
                cursor_position=len(document.text))  # Move cursor to end


print("\n========================================================")
print(pyfiglet.figlet_format('pyHide')+'\n')
print(colored('github.com/omnone/pyHide', 'cyan'))
print("\n========================================================")

questions = [
    {
        'type': 'list',
        'name': 'op',
        'message': 'Select operation:',
        'choices': ['Encode Image', 'Decode Image', 'Quit'],
    },
    {
        'type': 'input',
        'name': 'imgPath',
        'message': 'Enter image path:',
        'validate': PathValidator,
        'when': lambda userInput: userInput['op'] != 'Quit'

    },
    {
        'type': 'password',
        'name': 'passw',
        'message': 'Enter password:',
        'when': lambda userInput: userInput['op'] != 'Quit'

    },
    {
        'type': 'input',
        'name': 'message',
        'message': 'Enter message:',
        'when': lambda userInput: userInput['op'] != 'Decode Image' and userInput['op'] != 'Quit'
    },

]

userInput = prompt(questions)

print("\n========================================================")

if userInput['op'] == 'Encode Image':
    message = userInput['message']
    lsbSteg.encodeImage(
        userInput['imgPath'], userInput['message'], password=userInput['passw'])
elif userInput['op'] == 'Decode Image':
    mess = lsbSteg.decodeImage(
        userInput['imgPath'], password=userInput['passw'])
else:
    sys.exit(0)
