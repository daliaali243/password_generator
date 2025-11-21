import tkinter as tk
from tkinter import ttk, messagebox
import random
import string
import re


class PasswordManager:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Generator & Analyzer")
        self.root.geometry("500x400")
        self.root.resizable(False, False)

        self.setup_ui()

    def setup_ui(self):
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))


        title_label = ttk.Label(main_frame, text="Password Generator & Analyzer",
                                font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))

        entry_frame = ttk.LabelFrame(main_frame, text="Analyze Password", padding="10")
        entry_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(0, 10))

        ttk.Label(entry_frame, text="Enter Password:").grid(row=0, column=0, sticky=tk.W)

        self.password_entry = ttk.Entry(entry_frame, width=30, show="•")
        self.password_entry.grid(row=0, column=1, padx=(10, 0))

        analyze_btn = ttk.Button(entry_frame, text="Analyze", command=self.analyze_password)
        analyze_btn.grid(row=0, column=2, padx=(10, 0))

        # Show/Hide password checkbox
        self.show_password = tk.BooleanVar()
        show_cb = ttk.Checkbutton(entry_frame, text="Show", variable=self.show_password,
                                  command=self.toggle_password_visibility)
        show_cb.grid(row=0, column=3, padx=(10, 0))


        self.strength_label = ttk.Label(entry_frame, text="", font=('Arial', 10, 'bold'))
        self.strength_label.grid(row=1, column=0, columnspan=4, pady=(10, 0), sticky=tk.W)


        gen_frame = ttk.LabelFrame(main_frame, text="Generate Password", padding="10")
        gen_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 10))


        ttk.Label(gen_frame, text="Length:").grid(row=0, column=0, sticky=tk.W)
        self.length_var = tk.IntVar(value=12)
        length_spin = ttk.Spinbox(gen_frame, from_=8, to=32, width=10, textvariable=self.length_var)
        length_spin.grid(row=0, column=1, sticky=tk.W, padx=(10, 0))


        self.use_uppercase = tk.BooleanVar(value=True)
        self.use_lowercase = tk.BooleanVar(value=True)
        self.use_numbers = tk.BooleanVar(value=True)
        self.use_symbols = tk.BooleanVar(value=True)

        ttk.Checkbutton(gen_frame, text="Uppercase (A-Z)", variable=self.use_uppercase).grid(row=1, column=0,
                                                                                             sticky=tk.W)
        ttk.Checkbutton(gen_frame, text="Lowercase (a-z)", variable=self.use_lowercase).grid(row=1, column=1,
                                                                                             sticky=tk.W)
        ttk.Checkbutton(gen_frame, text="Numbers (0-9)", variable=self.use_numbers).grid(row=2, column=0, sticky=tk.W)
        ttk.Checkbutton(gen_frame, text="Symbols (!@#)", variable=self.use_symbols).grid(row=2, column=1, sticky=tk.W)


        gen_btn = ttk.Button(gen_frame, text="Generate Password", command=self.generate_password)
        gen_btn.grid(row=3, column=0, columnspan=2, pady=(10, 0))


        self.generated_password = ttk.Entry(gen_frame, width=30, font=('Arial', 10))
        self.generated_password.grid(row=4, column=0, columnspan=2, pady=(10, 0))

        copy_btn = ttk.Button(gen_frame, text="Copy", command=self.copy_password)
        copy_btn.grid(row=4, column=2, padx=(10, 0))

        results_frame = ttk.LabelFrame(main_frame, text="Analysis Results", padding="10")
        results_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))

        self.results_text = tk.Text(results_frame, height=6, width=50, font=('Arial', 9))
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E))

        scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.results_text.yview)
        scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        self.results_text.configure(yscrollcommand=scrollbar.set)

    def toggle_password_visibility(self):
        if self.show_password.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="•")

    def analyze_password(self):
        password = self.password_entry.get()
        if not password:
            messagebox.showwarning("Warning", "Please enter a password to analyze")
            return

        strength, score, feedback = self.check_password_strength(password)

        # Update strength label with color
        self.strength_label.config(text=f"Strength: {strength} (Score: {score}/100)")
        if strength == "Very Weak":
            self.strength_label.config(foreground="red")
        elif strength == "Weak":
            self.strength_label.config(foreground="orange")
        elif strength == "Good":
            self.strength_label.config(foreground="blue")
        elif strength == "Strong":
            self.strength_label.config(foreground="green")
        else:  # Very Strong
            self.strength_label.config(foreground="dark green")

        # Display detailed analysis
        self.results_text.delete(1.0, tk.END)
        self.results_text.insert(tk.END, f"Password Analysis:\n")
        self.results_text.insert(tk.END, f"• Length: {len(password)} characters\n")
        self.results_text.insert(tk.END, f"• Strength: {strength}\n")
        self.results_text.insert(tk.END, f"• Score: {score}/100\n\n")
        self.results_text.insert(tk.END, "Suggestions:\n")
        for suggestion in feedback:
            self.results_text.insert(tk.END, f"• {suggestion}\n")

    def check_password_strength(self, password):
        score = 0
        feedback = []


        length = len(password)
        if length >= 12:
            score += 25
        elif length >= 8:
            score += 15
        else:
            score += 5
            feedback.append("Use at least 8 characters (12+ recommended)")


        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digit = bool(re.search(r'[0-9]', password))
        has_symbol = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password))

        if has_upper:
            score += 15
        else:
            feedback.append("Add uppercase letters")

        if has_lower:
            score += 15
        else:
            feedback.append("Add lowercase letters")

        if has_digit:
            score += 15
        else:
            feedback.append("Add numbers")

        if has_symbol:
            score += 15
        else:
            feedback.append("Add symbols")


        char_types = sum([has_upper, has_lower, has_digit, has_symbol])
        if char_types >= 3:
            score += 15


        common_patterns = ['123', 'abc', 'password', 'qwerty', 'admin']
        if any(pattern in password.lower() for pattern in common_patterns):
            score -= 10
            feedback.append("Avoid common patterns and words")


        if score >= 90:
            strength = "Very Strong"
        elif score >= 70:
            strength = "Strong"
        elif score >= 50:
            strength = "Good"
        elif score >= 30:
            strength = "Weak"
        else:
            strength = "Very Weak"

        return strength, min(100, max(0, score)), feedback

    def generate_password(self):
        length = self.length_var.get()


        char_pool = ""
        if self.use_lowercase.get():
            char_pool += string.ascii_lowercase
        if self.use_uppercase.get():
            char_pool += string.ascii_uppercase
        if self.use_numbers.get():
            char_pool += string.digits
        if self.use_symbols.get():
            char_pool += "!@#$%^&*()_+-=[]{}|;:,.<>?"

        if not char_pool:
            messagebox.showwarning("Warning", "Please select at least one character type")
            return


        password = ''.join(random.choice(char_pool) for _ in range(length))
        self.generated_password.delete(0, tk.END)
        self.generated_password.insert(0, password)

        
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
        self.analyze_password()

    def copy_password(self):
        password = self.generated_password.get()
        if password:
            self.root.clipboard_clear()
            self.root.clipboard_append(password)
            messagebox.showinfo("Success", "Password copied to clipboard!")
        else:
            messagebox.showwarning("Warning", "No password to copy")


def main():
    root = tk.Tk()
    app = PasswordManager(root)
    root.mainloop()


if __name__ == "__main__":
    main()