import lsbSteg
import pyfiglet
from PyInquirer import prompt
from os import path
from prompt_toolkit.validation import Validator, ValidationError
import sys
from termcolor import colored
import time

import itertools
import threading
import time
import sys

done = False
#here is the animation
def animate(mode):
    for c in itertools.cycle(['|', '/', '-', '\\']):
        if done:
            break
        sys.stdout.write(f'\r[*]{mode} .. ' + c)
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write(f'\r\n[+]{mode} finished!  ')



class PathValidator(Validator):
    def validate(self, document):
        imgPath = path.exists(document.text)
        if not imgPath:
            raise ValidationError(
                message='[-]Please enter a valid file path',
                cursor_position=len(document.text))  # Move cursor to end


print("\n========================================================")
print(pyfiglet.figlet_format('pyRanoid')+'\n')
print(colored('(github.com/omnone/pyRanoid)', 'cyan'))
print("\n========================================================")

questions = [
    {
        'type': 'list',
        'name': 'op',
        'message': 'Select operation:',
        'choices': ['encrypt Image', 'decrypt Image', 'Quit'],
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
        'when': lambda userInput: userInput['op'] != 'decrypt Image' and userInput['op'] != 'Quit'
    },
    

]

userInput = prompt(questions)

print("\n========================================================")

if userInput['op'] == 'encrypt Image':
    message = userInput['message']
    
    t = threading.Thread(target=animate,args=["Encoding"],daemon=True)
    t.start()

    lsbSteg.encryptImage(userInput['imgPath'], userInput['message'], password=userInput['passw'])
    
    time.sleep(5)
    done = True
    
elif userInput['op'] == 'decrypt Image':

    t = threading.Thread(target=animate,args=["Decoding"],daemon=True)
    t.start()

    decryptedMessage = lsbSteg.decryptImage(
        userInput['imgPath'], password=userInput['passw'])
        
    time.sleep(5)
    done = True
    print(f'\n[+]Decrypted Message:\n {decryptedMessage}')

else:
    sys.exit(0)
