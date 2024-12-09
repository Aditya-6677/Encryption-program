import time 

def encrypt(text, shift, password):
    """
    Function to encrypt the given text using Caesar cipher technique.
    Each character in the text is shifted by the specified number of positions.
    """
    result = ""

    # Encrypting each letter
    for char in text:
        if char.isupper():
            result += chr((ord(char) + shift - 65) % 26 + 65)
        elif char.islower():
            result += chr((ord(char) + shift - 97) % 26 + 97)
        elif char.isdigit():
            result += chr((ord(char) + shift - 48) % 10 + 48)
        else:
            result += char

    return result, password

def password_check(password_entered, password):
    """
    Function to check if the entered password matches the set password.
    Provides the user with 5 attempts to enter the correct password.
    """
    for attempts_left in range(5, 0, -1):
        if password_entered != password:
            print(f"Wrong password, you have {attempts_left - 1} chances left")
            if attempts_left - 1 == 0:
                break
            password_entered = input("Try again: ")
        else:
            print("Your password is correct. Decryption will proceed.")
            return True

    return False


def decrypt(text, shift, password):
    """
    Function to decrypt the given text using Caesar cipher technique.
    The user needs to enter the correct password to access the decrypted text.
    """
    result = ""

    # Decrypting each letter of the provided code
    for char in text:
        if char.isupper():
            result += chr((ord(char) - shift - 65) % 26 + 65)
        elif char.islower():
            result += chr((ord(char) - shift - 97) % 26 + 97)
        elif char.isdigit():
            result += chr((ord(char) - shift - 48) % 10 + 48)
        else:
            result += char

    password_entered = input("Enter the password to decrypt: ")

    if password_check(password_entered, password):
        return result
    else:
        return "You entered the wrong password too many times."

def show_instructions():
    """
    Function to display instructions to the user.
    """
    print("""
Welcome to my Encryption/Decryption Program!

Features:
1. Encrypt any text with a password.
2. Decrypt encrypted text using the same password.
3. Choose a shift value to customize your encryption.

Instructions:
- When encrypting, enter a sentence, a shift value, and a password.
- When decrypting, you must enter the exact password used for encryption.
- You have 5 attempts to enter the correct password during decryption.
- Only alphanumeric characters and spaces are affected by this program.

Enjoy using the program!
    """)

def main():
    """
    Main function to provide a simple menu interface for encryption and decryption.
    Prompts the user to choose between encrypting or decrypting a text.
    """
    show_instructions()

    while True:
        print("\nMenu:")
        print("1. Encrypt text")
        print("2. Decrypt text")
        print("3. View instructions")
        print("4. Exit")
        choice = input("Type 1 to encrypt, 2 to decrypt, 3 for instructions, or 4 to exit: ")

        if choice.isdigit() and 1 <= int(choice) <= 4:
            choice = int(choice)
        else:
            print("Invalid input. Please enter a number between 1 and 4.")
            continue

        if choice == 1:
            text = input("Enter the sentence to be encrypted: ")
            while True:
                try:
                    shift = int(input("Enter a shift value (numeric): "))
                    break
                except ValueError:
                    print("Please enter a valid number for the shift.")

            password = input("Enter a password. It will be used to decrypt the code provided: ")
            encrypted_text, password = encrypt(text, shift, password)
            #adding a 3 second delay before printing the encrypted text
            time.sleep(3) 

            print("Encrypted Text: ", encrypted_text)
            print(f"Length of encrypted text: {len(encrypted_text)} characters")

        elif choice == 2:
            encrypted_text = input("Enter the sentence to be decrypted: ")
            while True:
                try:
                    shift = int(input("Enter the shift value used during encryption: "))
                    break
                except ValueError:
                    print("Please enter a valid number for the shift.")

            decrypted_text = decrypt(encrypted_text, shift, password)
            #adding a 3 second delay brfore printing the decrypted text
            time.sleep(3)

            print("Decrypted Text: ", decrypted_text)
            print(f"Length of decrypted text: {len(decrypted_text)} characters")

        elif choice == 3:
            show_instructions()

        elif choice == 4:
            print("Goodbye!")
            break

main()
