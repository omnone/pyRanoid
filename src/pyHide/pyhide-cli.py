# ============================================================================================
# MIT License
# Copyright (c) 2020 Konstantinos Bourantas

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the 'Software'), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
# ============================================================================================

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
