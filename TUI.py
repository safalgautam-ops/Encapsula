from textual.app import App
from textual.widgets import Button, Static, Footer, Header, Input, TextArea
from textual.containers import ScrollableContainer, Vertical, Horizontal, Container
from textual import on
from textual.screen import Screen

import tkinter as tk
from tkinter import filedialog
import os

from main import check_file_type, encode_stego, decode_stego

class EncodeScreen(Screen):

    def compose(self):
        yield Container(
            Static("Welcome to the Encapsula:Steganography Toolkit", id="title", classes="texts"),
            Static("Encode Your Message Here: ", id="encode_screen", classes="texts"),
            Button("Upload File", variant="primary", id="upload_button"),
            Input(placeholder="No files selected", id="file_input", classes="input-field", disabled=True),
            Static("Enter your message here:", id="textbox", classes="texts"),
            TextArea(id="message_input", classes="input-field"),
            Static("Set your password here:", id="passbox", classes="texts"),
            Input(placeholder="Type your password here...", id="password_input", classes="input-field", password=True),
            Page2functional()
        )

    @on(Button.Pressed, "#upload_button") 
    def upload_file(self):
        root = tk.Tk()
        root.withdraw()
        selected_file_path = filedialog.askopenfilename(
            title="Select a file",
            filetypes=[
                ("PNG Image", "*.png"),
                ("JPEG Image", "*.jpg;*.jpeg"),
                ("WEBP Image", "*.webp"),
                ("Text File", "*.txt"),
                ("PDF Document", "*.pdf"),
                ("Word Document", "*.doc;*.docx"),
                ("PowerPoint Presentation", "*.pptx"),
                ("Excel Spreadsheet", "*.xls;*.xlsx"),
                ("All Files", "*.*")
            ]
        )
        root.destroy()
        if selected_file_path: 
            if check_file_type(selected_file_path):
                self.query_one("#file_input", Input).value = selected_file_path
                _, ext = os.path.splitext(selected_file_path)
                self.uploaded_ext = ext.lower() if ext else ".png"
                self.uploaded_file_path = selected_file_path
            else:
                self.query_one("#file_input", Input).value = "Invalid File Format"

class Page2functional(Static):
    def compose(self):
        yield Horizontal(
            Button("Hide Now", variant="error", id="hiding_button"),
            Button("Go Back", variant="success", id="back_button"),
            id="button-group"
        )
        
    @on(Button.Pressed, "#hiding_button")
    def encode_message(self):
        encode_screen = self.app.screen_stack[-1] #gets the current screen which is EncodeScreen
        file_value = encode_screen.query_one("#file_input", Input).value #accessing the widgets 
        msg_value = encode_screen.query_one("#message_input", TextArea).text
        pwd_value = encode_screen.query_one("#password_input", Input).value

        # Simple check
        if not file_value or file_value == "Invalid File Format":
            encode_screen.query_one("#file_input", Input).value = "Please upload a valid file!"
            return
        if not msg_value.strip():
            encode_screen.query_one("#textbox", Static).update("Please enter a message!")
            return
        if not pwd_value.strip():
            encode_screen.query_one("#passbox", Static).update("Please enter a password!")
            return

        # If all fields are filled, proceed
        ext = getattr(encode_screen, 'uploaded_ext', '.png')
        input_file_path = getattr(encode_screen, 'uploaded_file_path', "") #accessing the attribute of the object
        # Pass message and password to Save_Encoding
        self.app.push_screen(Save_Encoding(ext=ext, message=msg_value, password=pwd_value, input_file_path=input_file_path))

    @on(Button.Pressed, "#back_button")
    def go_back(self):
        self.app.pop_screen()

class Save_Encoding(Screen):
    def __init__(self, ext="", message="", password="", input_file_path=""):
        super().__init__()
        self.ext = ext
        self.message = message
        self.password = password
        self.input_file_path = input_file_path

    def compose(self):
        yield Container(
            Static("Welcome to the Encapsula:Steganography Toolkit", id="title", classes="texts"),
            Static("Save Your Encoded Message Here: ", id="save_screen", classes="texts"),
            Button("Save File", variant="default", id="save_button"),
            Input(placeholder="No files selected", id="file_input", classes="input-field", disabled=True),
            Static("", id="process_input", classes="input-field"),
            FinalScreen_Buttons()
        )

    @on(Button.Pressed, "#save_button")
    def save_file(self):
        root = tk.Tk()
        root.withdraw()
        output_file_path = filedialog.asksaveasfilename(
            title="Save file as",
            defaultextension=self.ext,
            filetypes=[(f"{self.ext.upper()} File", f"*{self.ext}")]
        )
        root.destroy()
        if output_file_path:
            self.query_one("#file_input", Input).value = output_file_path

    @on(Button.Pressed, "#done_button")
    def done(self):
        output_file_path = self.query_one("#file_input", Input).value
        if not output_file_path:
            self.query_one("#process_input", Static).update("Please select a save file first!")
            return

        self.query_one("#process_input", Static).update("Encoding, please wait...")

        # Directly call encode_stego (no threading)
        result = encode_stego(
            self.input_file_path,
            self.message,
            self.password,
            output_file_path
        )
        self.show_result(result)

    def show_result(self, result):
        self.query_one("#process_input", Static).update(result)

class FinalScreen_Buttons(Static):
    def compose(self):
        yield Horizontal(
            Button("Done", variant="error", id="done_button"),
            Button("Go Back", variant="success", id="back_button"),
            id="button-group"
        )

    @on(Button.Pressed, "#back_button")
    def go_back(self):
        self.app.pop_screen()

class DecodeScreen(Screen): 
    def compose(self):
        yield Container(
            Static("Welcome to the Encapsula:Steganography Toolkit", id="title", classes="texts"),
            Static("Decode Your Message Here: ", id="decode_screen", classes="texts"),
            Button("Upload File", variant="primary", id="upload_button"),
            Input(placeholder="No files selected", id="file_input", classes="input-field", disabled=True),
            Static("Enter your password here:", id="passbox", classes="texts"),
            Input(placeholder="Type your password here...", id="password_input", classes="input-field", password=True),
            Static(id="pswd_check", classes="texts"),
            Page3functional()
        )

    @on(Button.Pressed, "#upload_button")
    def upload_file(self):
        root = tk.Tk()
        root.withdraw()
        new_file_path = filedialog.askopenfilename(
            title="Select a file",
            filetypes=[
                ("PNG Image", "*.png"),
                ("JPEG Image", "*.jpg;*.jpeg"),
                ("WEBP Image", "*.webp"),
                ("Text File", "*.txt"),
                ("PDF Document", "*.pdf"),
                ("Word Document", "*.doc;*.docx"),
                ("PowerPoint Presentation", "*.pptx"),
                ("Excel Spreadsheet", "*.xls;*.xlsx"),
                ("All Files", "*.*")
            ]
        )
        root.destroy()
        if new_file_path:
            self.query_one("#file_input", Input).value = new_file_path
        

class Page3functional(Static):
    def compose(self):
        yield Horizontal(
            Button("Show Now", variant="error", id="showing_button"),
            Button("Go Back", variant="success", id="back_button"),
            id="button-group"
        )
    @on(Button.Pressed, "#showing_button")
    def decode_file(self):
        decode_screen = self.app.screen_stack[-1]
        file_value = decode_screen.query_one("#file_input", Input).value
        pwd_value = decode_screen.query_one("#password_input", Input).value
        if pwd_value.strip() == "":
            decode_screen.query_one("#pswd_check", Static).update("Please enter correct password!")
        else:
            decoded_mesg = decode_stego(file_value, pwd_value)
            decode_screen.query_one("#pswd_check", Static).update("Decoding, please wait...")
            self.show_result(decoded_mesg)
            
    def show_result(self, decoded_mesg):
        decode_screen = self.app.screen_stack[-1]
        if decoded_mesg == "Error":
            decode_screen.query_one("#pswd_check", Static).update("Incorrect password. Please try again.")
        else:
            decode_screen.query_one("#pswd_check", Static).update(f"The hidden message is: {decoded_mesg}")

    @on(Button.Pressed, "#back_button")
    def go_back(self):
        self.app.pop_screen()

class Frontdisplay(Static):
    def compose(self):
        yield Vertical(
            Static("Welcome to the Encapsula:Steganography Toolkit", id="title", classes="texts"),
            Static("This tool was designed and developed by", id="subtitle", classes="texts"),
            Static(r"""
 ____  ____    __    ____  ____  _  _  ____ 
(  _ \( ___)  /__\  (  _ \( ___)( \/ )( ___)    
 )(_) ))__)  /(__)\  )(_) ))__)  \  /  )__)    
(____/(____)(__)(__)(____/(____) (__) (____)
                                @Safal Gautam
""", id="ascii", classes="texts"),
            Static("github: safalgautam-ops", id="github", classes="texts"),
            Static("This toolkit allows you to hide messages in images or files.", id="description", classes="texts"),
            Static("Select an option below to get started:", id="instruction", classes="texts"),
            Frontfunctional(),
            id="text-group"
        )

class Frontfunctional(Static):
    def compose(self):
        yield Horizontal(
            Button("Encode", variant="error", id="encode_button"),
            Button("Decode", variant="success", id="decode_button"),
            id="button-group"
        )

    @on(Button.Pressed, "#encode_button")
    def encode_message(self):
        self.app.push_screen(EncodeScreen())

    @on(Button.Pressed, "#decode_button")
    def decode_message(self):
        self.app.push_screen(DecodeScreen())

class CheckEncValues(Static):
    def compose(self):
        pass

class Frontpage(App):
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("e", "encode_message", "Encode Message"),
        ("d", "decode_message", "Decode Message")
    ]

    CSS_PATH = "style.css"

    def compose(self):
        yield Header()
        with ScrollableContainer(id="mainUI"):
            yield Container(
                Frontdisplay()
            )
        yield Footer()

def main():
    app = Frontpage()
    app.run()

if __name__ == "__main__":
    main()
