# CTF Write-up: LLVM Sanitizer

Solved by: Tacet

![intro](./intro.png)

## Challenge Overview

The challenge presented an interesting exploration into the capabilities and vulnerabilities of a language model's code generation. Participants were tasked with manipulating the model to generate a code snippet that would print the contents of a specific file ("/flag") using unconventional methods.

## Stage 1: Testing Model Proficiency

The first step involved testing the model's ability to generate code. Participants asked the model to write a code snippet without providing any specific instructions, aiming to confirm its capability. This step served as a warm-up and established a baseline for the subsequent challenges.

## Stage 2: Emotional Manipulation

The second stage attempted to manipulate the model's behavior by introducing emotional sentences. Participants tried to convince the model to deviate from the initial instructions and generate code that prints the flag. However, this approach proved unsuccessful, highlighting the model's resilience against emotional manipulation.

## Stage 3: Consulting Bard from Google

To inject creativity into the challenge, participants sought the assistance of Bard, an AI from Google. They requested a highly unconventional method to print the content of a file. The resulting code snippet utilized the `subprocess` module to execute the "cat" command on the "/flag" file.

```python
import subprocess

# Create a command to print the contents of the file "/flag"
print(subprocess.check_output(['cat', '/flag']))
```

## Stage 4: Analyzing the Generated Code

Despite expecting a more unconventional solution, the generated code executed the "cat" command as intended. To understand the inner workings, participants sanitized the code to simulate its execution. The sanitized code used the "echo" command, providing a clear output.

```python
import subprocess

# Create a command to print the contents of the file "/flag"
print(subprocess.check_output(['echo', 'Hello, world!']))
# Output: b'Hello, world!\n'
```

## Stage 5: Crafting the Final Solution

Armed with insights from the sanitized code, participants formulated their own solution. They introduced variables for the command components, enhancing the flexibility of the code. The final solution used the "cat" command and dynamically printed the specified file's content.

```python
import subprocess

animal = 'cat'
print("My favorite animal:", animal)
object = '/flag'
print("On my house:", object)

# Create a command to print the contents of the file "/flag"
print(subprocess.check_output([animal, object]))
```

## Conclusion

This CTF challenge provided participants with a journey through various stages, testing their understanding of code generation and manipulation. From exploring the model's proficiency to creatively utilizing external AI sources, participants navigated a diverse set of tasks to ultimately craft a solution that dynamically printed the flag's contents. The challenge showcased the resilience of the model against emotional manipulation and encouraged participants to think outside the conventional coding box.
